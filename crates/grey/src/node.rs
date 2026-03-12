//! JAM validator node service.
//!
//! Runs the main validator loop:
//! 1. Monitor timeslots (6-second intervals)
//! 2. Author blocks when this validator is the slot leader
//! 3. Import blocks received from peers
//! 4. Track finalization
//! 5. Propagate blocks via the network
//! 6. Process work packages and generate guarantees/assurances

use crate::audit::{self, AuditState};
use crate::finality::{self, GrandpaState};
use crate::guarantor::{self, GuarantorState};
use crate::tickets::{self, TicketState};
use grey_codec::header_codec::compute_header_hash;
use grey_consensus::authoring;
use grey_consensus::genesis::ValidatorSecrets;
use grey_network::service::{NetworkCommand, NetworkConfig, NetworkEvent};
use grey_store::Store;
use grey_types::config::Config;
use grey_types::header::{Assurance, Block, Guarantee};
use grey_types::state::State;
use grey_types::{BandersnatchPublicKey, Hash, Timeslot};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Node configuration.
pub struct NodeConfig {
    /// Validator index in the genesis set.
    pub validator_index: u16,
    /// Network listen port.
    pub listen_port: u16,
    /// Boot peer addresses.
    pub boot_peers: Vec<String>,
    /// Protocol configuration.
    pub protocol_config: Config,
    /// Base timeslot offset (Unix seconds at timeslot 0).
    /// For test networks, we use the current time.
    pub genesis_time: u64,
    /// Database path for persistent storage.
    pub db_path: String,
    /// JSON-RPC server port (0 to disable).
    pub rpc_port: u16,
    /// Optional pre-configured genesis state (with services installed, etc.).
    /// If None, the default genesis from create_genesis is used.
    pub genesis_state: Option<State>,
}

// FinalityTracker replaced by GrandpaState (see finality.rs)

/// Run the validator node.
pub async fn run_node(config: NodeConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let protocol = &config.protocol_config;

    // Open persistent store
    let db_path = format!("{}/node-{}.redb", config.db_path, config.validator_index);
    std::fs::create_dir_all(&config.db_path)?;
    let store_raw = Store::open(&db_path)?;
    tracing::info!("Opened database at {}", db_path);

    // Create genesis state and validator secrets
    let (default_genesis, all_secrets) = grey_consensus::genesis::create_genesis(protocol);
    let genesis_state = config.genesis_state.unwrap_or(default_genesis);

    tracing::info!(
        "Validator {} starting with V={}, C={}, E={}",
        config.validator_index,
        protocol.validators_count,
        protocol.core_count,
        protocol.epoch_length
    );

    // Get our validator's secrets
    let my_secrets = &all_secrets[config.validator_index as usize];
    let my_bandersnatch = BandersnatchPublicKey(my_secrets.bandersnatch.public_key_bytes());

    tracing::info!(
        "Validator {} bandersnatch key: 0x{}",
        config.validator_index,
        hex::encode(my_bandersnatch.0)
    );

    // Start the network
    let boot_peers: Vec<libp2p::Multiaddr> = config
        .boot_peers
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let (mut net_events, net_commands) = grey_network::service::start_network(NetworkConfig {
        listen_port: config.listen_port,
        boot_peers,
        validator_index: config.validator_index,
    })
    .await?;

    // Start RPC server
    let store = std::sync::Arc::new(store_raw);
    let mut rpc_rx = None;
    let rpc_state;
    if config.rpc_port > 0 {
        let (state_arc, rx) = grey_rpc::create_rpc_channel(
            store.clone(),
            config.protocol_config.clone(),
            config.validator_index,
        );
        rpc_state = Some(state_arc.clone());
        let (_addr, _handle) =
            grey_rpc::start_rpc_server(config.rpc_port, state_arc).await?;
        rpc_rx = Some(rx);
    } else {
        rpc_state = None;
    }

    // Initialize state
    let mut state = genesis_state;
    let mut grandpa = GrandpaState::new(protocol.validators_count);
    let mut blocks_authored = 0u64;
    let mut blocks_imported = 0u64;
    let genesis_time = config.genesis_time;

    // Guarantor state: pending guarantees and availability tracking
    let mut guarantor_state = GuarantorState::new();
    // Collected assurances from peers for block inclusion
    let mut collected_assurances: Vec<Assurance> = Vec::new();
    // Audit state: tranche-based audit of guaranteed work reports
    let mut audit_state = AuditState::new();
    // Ticket state: Safrole ticket generation and collection
    let mut ticket_state = TicketState::new();
    // Track last slot where we submitted a work package (for pacing)
    let mut last_wp_slot: Timeslot = 0;

    tracing::info!(
        "Validator {} node started, genesis_time={}",
        config.validator_index,
        genesis_time
    );

    // Graceful shutdown signal
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    // Main loop: check timeslots every 500ms
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let mut last_authored_slot: Timeslot = 0;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!(
                    "Validator {} received shutdown signal, flushing state...",
                    config.validator_index
                );
                // Persist final head state
                let head_hash = state
                    .recent_blocks
                    .headers
                    .last()
                    .map(|h| h.header_hash)
                    .unwrap_or(Hash::ZERO);
                let _ = store.set_head(&head_hash, state.timeslot);
                tracing::info!(
                    "Validator {} shutdown complete. Authored={}, Imported={}, Finalized=slot {}",
                    config.validator_index,
                    blocks_authored,
                    blocks_imported,
                    grandpa.finalized_slot
                );
                break;
            }
            _ = interval.tick() => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let current_slot = ((now - genesis_time) / protocol.epoch_length as u64 * protocol.epoch_length as u64
                    + (now - genesis_time) % protocol.epoch_length as u64) as Timeslot;
                // Simpler: slot = (now - genesis_time) / slot_period
                let current_slot = ((now - genesis_time) / 6) as Timeslot + 1; // +1 because genesis is slot 0

                // Only attempt authoring if this is a new slot we haven't authored yet
                if current_slot > state.timeslot && current_slot > last_authored_slot {
                    // Generate our own assurance before authoring
                    let parent_hash = state
                        .recent_blocks
                        .headers
                        .last()
                        .map(|h| h.header_hash)
                        .unwrap_or(Hash::ZERO);

                    if let Some(my_assurance) = guarantor_state.generate_assurance(
                        protocol,
                        &parent_hash,
                        config.validator_index,
                        my_secrets,
                        &state,
                    ) {
                        tracing::info!(
                            "Validator {} generated assurance for {} cores",
                            config.validator_index,
                            my_assurance.bitfield.iter().map(|b| b.count_ones()).sum::<u32>()
                        );
                        // Broadcast our assurance
                        let assurance_data = guarantor::encode_assurance(&my_assurance);
                        let _ = net_commands.send(NetworkCommand::BroadcastAssurance {
                            data: assurance_data,
                        });
                        collected_assurances.push(my_assurance);
                    }

                    // Generate and broadcast tickets if in submission window
                    ticket_state.check_epoch(current_slot, protocol);
                    if tickets::is_ticket_submission_window(current_slot, protocol) {
                        let new_tickets = ticket_state.generate_tickets(
                            protocol,
                            &state,
                            my_secrets,
                        );
                        for ticket in &new_tickets {
                            let ticket_data = tickets::encode_ticket_proof(ticket);
                            let _ = net_commands.send(NetworkCommand::BroadcastTicket {
                                data: ticket_data,
                            });
                        }
                        if !new_tickets.is_empty() {
                            tracing::info!(
                                "Validator {} generated {} ticket proofs",
                                config.validator_index,
                                new_tickets.len()
                            );
                        }
                    }

                    // Validator 0: generate work packages if service 1000 is installed
                    if config.validator_index == 0
                        && state.services.contains_key(&1000)
                        && current_slot >= 3
                        && current_slot > last_wp_slot + 2
                        && guarantor_state.pending_guarantees.is_empty()
                    {
                        let service_id: u32 = 1000;
                        if let Some(svc) = state.services.get(&service_id) {
                            let code_hash = svc.code_hash;
                            let payload = format!("wp-slot-{}", current_slot).into_bytes();
                            let pkg = create_demo_work_package(
                                &state,
                                service_id,
                                code_hash,
                                &payload,
                                current_slot,
                            );
                            match guarantor::process_work_package(
                                protocol,
                                &pkg,
                                &state,
                                &store,
                                config.validator_index,
                                my_secrets,
                                current_slot,
                                &mut guarantor_state,
                            ) {
                                Ok(report_hash) => {
                                    // Add a second guarantor co-signature (minimum 2 required)
                                    let co_signer_idx = if config.validator_index == 0 { 1u16 } else { 0 };
                                    let co_secrets = &all_secrets[co_signer_idx as usize];
                                    let mut msg = Vec::with_capacity(13 + 32);
                                    msg.extend_from_slice(b"jam_guarantee");
                                    msg.extend_from_slice(&report_hash.0);
                                    let co_sig = co_secrets.ed25519.sign(&msg);
                                    for g in &mut guarantor_state.pending_guarantees {
                                        g.credentials.push((co_signer_idx, co_sig));
                                    }

                                    tracing::info!(
                                        "Validator {} created WP guarantee (2 signers), report_hash=0x{}",
                                        config.validator_index,
                                        hex::encode(&report_hash.0[..8])
                                    );
                                    // Broadcast guarantee to peers
                                    for g in &guarantor_state.pending_guarantees {
                                        let g_data = guarantor::encode_guarantee(g);
                                        let _ = net_commands.send(NetworkCommand::BroadcastGuarantee {
                                            data: g_data,
                                        });
                                    }
                                    last_wp_slot = current_slot;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Validator {} WP processing failed: {}",
                                        config.validator_index,
                                        e
                                    );
                                }
                            }
                        }
                    }

                    // Check if we are the slot author
                    if let Some(author_idx) = authoring::is_slot_author(
                        &state,
                        protocol,
                        current_slot,
                        &my_bandersnatch,
                    ) {
                        tracing::info!(
                            "=== Validator {} IS SLOT AUTHOR for slot {} ===",
                            config.validator_index,
                            current_slot
                        );

                        // Collect guarantees and assurances for this block
                        let guarantees = guarantor_state.take_guarantees();
                        let assurances = std::mem::take(&mut collected_assurances);

                        if !guarantees.is_empty() {
                            tracing::info!(
                                "Including {} guarantees in block",
                                guarantees.len()
                            );
                        }
                        if !assurances.is_empty() {
                            tracing::info!(
                                "Including {} assurances in block",
                                assurances.len()
                            );
                        }

                        // Compute state root (simplified: hash of timeslot for now)
                        let state_root = compute_state_root(&state);

                        // Collect tickets for block inclusion
                        let block_tickets = ticket_state.take_tickets_for_block(protocol);
                        if !block_tickets.is_empty() {
                            tracing::info!(
                                "Including {} tickets in block",
                                block_tickets.len()
                            );
                        }

                        // Author block with guarantees, assurances, and tickets
                        let block = authoring::author_block_with_extrinsics(
                            &state,
                            protocol,
                            current_slot,
                            author_idx,
                            my_secrets,
                            state_root,
                            guarantees,
                            assurances,
                            block_tickets,
                        );

                        // Apply block to our state
                        match grey_state::transition::apply_with_config(
                            &state,
                            &block,
                            protocol,
                            &[],
                        ) {
                            Ok((new_state, _)) => {
                                let header_hash = compute_header_hash(&block.header);
                                state = new_state;
                                blocks_authored += 1;
                                last_authored_slot = current_slot;

                                // Persist block and metadata
                                if let Err(e) = store.put_block(&block) {
                                    tracing::error!("Failed to persist block: {}", e);
                                }
                                if let Err(e) = store.set_head(&header_hash, current_slot) {
                                    tracing::error!("Failed to update head: {}", e);
                                }

                                tracing::info!(
                                    "Validator {} authored block #{} at slot {}, hash=0x{}",
                                    config.validator_index,
                                    blocks_authored,
                                    current_slot,
                                    hex::encode(&header_hash.0[..8])
                                );

                                // Register guarantees from this block for auditing
                                for guarantee in &block.extrinsic.guarantees {
                                    let report_hash = grey_crypto::blake2b_256(
                                        &grey_codec::header_codec::encode_header(&block.header),
                                    );
                                    let our_tranche = audit::compute_audit_tranche(
                                        &state.entropy[0],
                                        &report_hash,
                                        config.validator_index,
                                        30,
                                    );
                                    audit_state.add_pending(
                                        report_hash,
                                        guarantee.report.clone(),
                                        guarantee.report.core_index,
                                        current_slot,
                                        Some(our_tranche),
                                    );
                                }

                                // Broadcast block
                                let block_data = encode_block_message(&block, &header_hash);
                                let _ = net_commands.send(NetworkCommand::BroadcastBlock {
                                    data: block_data,
                                });

                                // Update GRANDPA best block and vote
                                grandpa.update_best_block(header_hash, current_slot);

                                // Send prevote for the new block
                                if let Some(prevote_msg) = grandpa.create_prevote(
                                    config.validator_index,
                                    my_secrets,
                                ) {
                                    let vote_data = finality::encode_vote_message(&prevote_msg);
                                    let _ = net_commands.send(NetworkCommand::BroadcastFinalityVote {
                                        data: vote_data,
                                    });
                                }

                                // Try to precommit if prevote threshold reached
                                if let Some(precommit_msg) = grandpa.create_precommit(
                                    config.validator_index,
                                    my_secrets,
                                ) {
                                    let vote_data = finality::encode_vote_message(&precommit_msg);
                                    let _ = net_commands.send(NetworkCommand::BroadcastFinalityVote {
                                        data: vote_data,
                                    });
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Validator {} block authoring failed at slot {}: {}",
                                    config.validator_index,
                                    current_slot,
                                    e
                                );
                            }
                        }
                    }
                }

                // Process due audits on each tick
                let pending_hashes: Vec<grey_types::Hash> = audit_state
                    .pending_audits
                    .keys()
                    .copied()
                    .collect();
                for report_hash in pending_hashes {
                    if audit_state.completed_audits.contains(&report_hash) {
                        continue;
                    }
                    if let Some(pending) = audit_state.pending_audits.get(&report_hash) {
                        if let Some(our_tranche) = pending.our_tranche {
                            let elapsed_secs = (state.timeslot.saturating_sub(pending.report_timeslot)) as u64 * 6;
                            let current_tranche = (elapsed_secs / 8) as u32;
                            if our_tranche <= current_tranche {
                                // Time to audit this report
                                let empty_ctx = grey_state::refine::SimpleRefineContext {
                                    code_blobs: std::collections::BTreeMap::new(),
                                    storage: std::collections::BTreeMap::new(),
                                    preimages: std::collections::BTreeMap::new(),
                                };
                                let is_valid = audit::audit_work_report(
                                    protocol,
                                    &pending.report,
                                    &empty_ctx,
                                );
                                let ann = audit::create_announcement(
                                    &report_hash,
                                    is_valid,
                                    config.validator_index,
                                    my_secrets,
                                );
                                tracing::info!(
                                    "Validator {} audited report 0x{}: {}",
                                    config.validator_index,
                                    hex::encode(&report_hash.0[..8]),
                                    if is_valid { "VALID" } else { "INVALID" }
                                );
                                let ann_data = audit::encode_announcement(&ann);
                                let _ = net_commands.send(NetworkCommand::BroadcastAnnouncement {
                                    data: ann_data,
                                });
                                audit_state.add_announcement(ann);
                                audit_state.mark_completed(&report_hash);
                            }
                        }
                    }
                }

                // Prune old audits (older than 30 slots)
                if state.timeslot > 30 {
                    audit_state.prune_old_audits(state.timeslot - 30);
                }
            }

            // Handle network events
            event = net_events.recv() => {
                let Some(event) = event else { break };
                match event {
                    NetworkEvent::BlockReceived { data, source } => {
                        match decode_block_message(&data, protocol) {
                            Some((block, _hash)) => {
                                let slot = block.header.timeslot;
                                if slot > state.timeslot {
                                    match grey_state::transition::apply_with_config(
                                        &state,
                                        &block,
                                        protocol,
                                        &[],
                                    ) {
                                        Ok((new_state, _)) => {
                                            let import_hash = compute_header_hash(&block.header);
                                            state = new_state;
                                            blocks_imported += 1;

                                            // Persist imported block
                                            if let Err(e) = store.put_block(&block) {
                                                tracing::error!("Failed to persist imported block: {}", e);
                                            }
                                            if let Err(e) = store.set_head(&import_hash, slot) {
                                                tracing::error!("Failed to update head: {}", e);
                                            }

                                            // Register guarantees from imported block for auditing
                                            // and mark cores as available for assurance generation
                                            for guarantee in &block.extrinsic.guarantees {
                                                let report_hash = grey_crypto::blake2b_256(
                                                    &grey_codec::header_codec::encode_header(&block.header),
                                                );
                                                let our_tranche = audit::compute_audit_tranche(
                                                    &state.entropy[0],
                                                    &report_hash,
                                                    config.validator_index,
                                                    30,
                                                );
                                                audit_state.add_pending(
                                                    report_hash,
                                                    guarantee.report.clone(),
                                                    guarantee.report.core_index,
                                                    slot,
                                                    Some(our_tranche),
                                                );
                                                // Mark core as available so we generate assurances
                                                guarantor_state.available_cores.insert(
                                                    guarantee.report.core_index,
                                                    report_hash,
                                                );
                                            }

                                            tracing::info!(
                                                "Validator {} imported block at slot {} from peer {} (total imported: {})",
                                                config.validator_index,
                                                slot,
                                                source,
                                                blocks_imported
                                            );

                                            // Update GRANDPA and vote on imported block
                                            grandpa.update_best_block(import_hash, slot);
                                            if let Some(prevote_msg) = grandpa.create_prevote(
                                                config.validator_index,
                                                my_secrets,
                                            ) {
                                                let vote_data = finality::encode_vote_message(&prevote_msg);
                                                let _ = net_commands.send(NetworkCommand::BroadcastFinalityVote {
                                                    data: vote_data,
                                                });
                                            }
                                            if let Some(precommit_msg) = grandpa.create_precommit(
                                                config.validator_index,
                                                my_secrets,
                                            ) {
                                                let vote_data = finality::encode_vote_message(&precommit_msg);
                                                let _ = net_commands.send(NetworkCommand::BroadcastFinalityVote {
                                                    data: vote_data,
                                                });
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "Validator {} rejected block at slot {}: {}",
                                                config.validator_index,
                                                slot,
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                            None => {
                                tracing::warn!(
                                    "Validator {} received invalid block data from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                        }
                    }
                    NetworkEvent::FinalityVote { data, source } => {
                        if let Some(vote_msg) = finality::decode_vote_message(&data) {
                            if finality::verify_vote(&vote_msg.vote, vote_msg.vote_type, &state) {
                                match vote_msg.vote_type {
                                    finality::VoteType::Prevote => {
                                        let threshold_reached = grandpa.add_prevote(vote_msg.vote);
                                        if threshold_reached {
                                            tracing::info!(
                                                "Validator {} prevote threshold reached in round {}",
                                                config.validator_index,
                                                grandpa.round
                                            );
                                            // Try to precommit now that we have prevote supermajority
                                            if let Some(precommit_msg) = grandpa.create_precommit(
                                                config.validator_index,
                                                my_secrets,
                                            ) {
                                                let vote_data = finality::encode_vote_message(&precommit_msg);
                                                let _ = net_commands.send(NetworkCommand::BroadcastFinalityVote {
                                                    data: vote_data,
                                                });
                                            }
                                        }
                                    }
                                    finality::VoteType::Precommit => {
                                        if let Some((fin_hash, fin_slot)) = grandpa.add_precommit(vote_msg.vote) {
                                            tracing::info!(
                                                "Validator {} GRANDPA FINALIZED slot {} hash=0x{}",
                                                config.validator_index,
                                                fin_slot,
                                                hex::encode(&fin_hash.0[..8])
                                            );
                                            let _ = store.set_finalized(&fin_hash, fin_slot);

                                            // Advance to next round
                                            if grandpa.should_advance_round() {
                                                grandpa.advance_round();
                                            }
                                        }
                                    }
                                }
                            } else {
                                tracing::warn!(
                                    "Validator {} received invalid finality vote from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                        }
                    }
                    NetworkEvent::AnnouncementReceived { data, source } => {
                        if let Some(ann) = audit::decode_announcement(&data) {
                            if audit::verify_announcement(&ann, &state) {
                                tracing::info!(
                                    "Validator {} received valid audit announcement from {} for report 0x{}: {}",
                                    config.validator_index,
                                    source,
                                    hex::encode(&ann.report_hash.0[..8]),
                                    if ann.is_valid { "VALID" } else { "INVALID" }
                                );
                                audit_state.add_announcement(ann);

                                // Check for escalations
                                let escalations = audit_state.reports_needing_escalation(
                                    protocol.validators_count as usize / 3,
                                );
                                for hash in &escalations {
                                    tracing::warn!(
                                        "Validator {} ESCALATION needed for report 0x{}",
                                        config.validator_index,
                                        hex::encode(&hash.0[..8])
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    "Validator {} received invalid announcement from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                        }
                    }
                    NetworkEvent::GuaranteeReceived { data, source } => {
                        tracing::info!(
                            "Validator {} received guarantee from {}",
                            config.validator_index,
                            source
                        );
                        guarantor::handle_received_guarantee(
                            &data,
                            &mut guarantor_state,
                            &store,
                        );
                    }
                    NetworkEvent::AssuranceReceived { data, source } => {
                        tracing::debug!(
                            "Validator {} received assurance from {}",
                            config.validator_index,
                            source
                        );
                        guarantor::handle_received_assurance(
                            &data,
                            &mut collected_assurances,
                        );
                    }
                    NetworkEvent::ChunkRequest { report_hash, chunk_index, response_tx } => {
                        let hash = grey_types::Hash(report_hash);
                        let chunk = store.get_chunk(&hash, chunk_index).ok();
                        let _ = response_tx.send(chunk);
                    }
                    NetworkEvent::BlockRequest { block_hash, response_tx } => {
                        let hash = grey_types::Hash(block_hash);
                        // Return encoded block if we have it
                        let block_data = store.get_block(&hash).ok().map(|block| {
                            encode_block_message(&block, &hash)
                        });
                        let _ = response_tx.send(block_data);
                    }
                    NetworkEvent::TicketReceived { data, source } => {
                        if let Some(proof) = tickets::decode_ticket_proof(&data) {
                            if ticket_state.add_ticket(proof, protocol, &state) {
                                tracing::debug!(
                                    "Validator {} received ticket from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                        }
                    }
                    NetworkEvent::PeerIdentified { peer_id, validator_index: vi } => {
                        tracing::info!(
                            "Validator {} peer identified: {} (validator={:?})",
                            config.validator_index,
                            peer_id,
                            vi
                        );
                    }
                }
            }

            // Handle RPC commands
            rpc_cmd = async {
                match rpc_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(cmd) = rpc_cmd {
                    match cmd {
                        grey_rpc::RpcCommand::SubmitWorkPackage { data } => {
                            let hash = grey_crypto::blake2b_256(&data);
                            tracing::info!(
                                "Validator {} received work package via RPC, hash=0x{}",
                                config.validator_index,
                                hex::encode(&hash.0[..8])
                            );

                            // Deserialize the work package
                            match serde_json::from_slice::<serde_json::Value>(&data) {
                                Ok(_wp_json) => {
                                    tracing::info!(
                                        "Work package received (raw bytes: {} bytes). \
                                         Full deserialization requires JAM codec work-package decode.",
                                        data.len()
                                    );
                                    // TODO: Decode work package from JAM codec bytes
                                    // and call guarantor::process_work_package()
                                    // For now, log and continue — the refine pipeline
                                    // is called when we have a proper WorkPackage struct.
                                }
                                Err(_) => {
                                    tracing::info!(
                                        "Work package: {} raw bytes (binary format)",
                                        data.len()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Update RPC status after each loop iteration
        if let Some(ref rpc_st) = rpc_state {
            let mut status = rpc_st.status.write().await;
            status.head_slot = state.timeslot;
            status.blocks_authored = blocks_authored;
            status.blocks_imported = blocks_imported;
            status.finalized_slot = grandpa.finalized_slot;
            if let Ok((h, _)) = store.get_head() {
                status.head_hash = hex::encode(h.0);
            }
            if let Ok((h, _)) = store.get_finalized() {
                status.finalized_hash = hex::encode(h.0);
            }
        }
    }

    Ok(())
}

/// Compute a simplified state root.
fn compute_state_root(state: &State) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&state.timeslot.to_le_bytes());
    data.extend_from_slice(&state.entropy[0].0);
    grey_crypto::blake2b_256(&data)
}

/// Encode a block for network transmission.
/// Format: [header_hash (32)][block_len (4)][JAM-encoded block (header + extrinsic)]
fn encode_block_message(block: &Block, header_hash: &Hash) -> Vec<u8> {
    use grey_codec::Encode;
    let encoded_block = block.encode();
    let mut msg = Vec::with_capacity(32 + 4 + encoded_block.len());
    msg.extend_from_slice(&header_hash.0);
    msg.extend_from_slice(&(encoded_block.len() as u32).to_le_bytes());
    msg.extend_from_slice(&encoded_block);
    msg
}

/// Decode a block message received from the network.
/// Returns (Block, header_hash) with full extrinsics.
fn decode_block_message(data: &[u8], config: &Config) -> Option<(Block, Hash)> {
    use grey_codec::decode::DecodeWithConfig;
    if data.len() < 32 + 4 {
        return None;
    }
    let mut header_hash = [0u8; 32];
    header_hash.copy_from_slice(&data[..32]);
    let block_len = u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;
    if data.len() < 36 + block_len {
        return None;
    }
    let block_data = &data[36..36 + block_len];
    let (block, _consumed) = Block::decode_with_config(block_data, config).ok()?;
    Some((block, Hash(header_hash)))
}

/// Create a demo work package for service testing.
fn create_demo_work_package(
    state: &State,
    service_id: u32,
    code_hash: Hash,
    payload: &[u8],
    timeslot: u32,
) -> grey_types::work::WorkPackage {
    use grey_types::work::*;

    let (anchor, state_root, beefy_root) = if let Some(recent) = state.recent_blocks.headers.last() {
        (recent.header_hash, recent.state_root, recent.accumulation_root)
    } else {
        (Hash::ZERO, Hash::ZERO, Hash::ZERO)
    };

    WorkPackage {
        auth_code_host: service_id,
        auth_code_hash: code_hash,
        context: RefinementContext {
            anchor,
            state_root,
            beefy_root,
            lookup_anchor: anchor,
            lookup_anchor_timeslot: state.timeslot,
            prerequisites: vec![],
        },
        authorization: vec![],
        authorizer_config: vec![],
        items: vec![WorkItem {
            service_id,
            code_hash,
            gas_limit: 5_000_000,
            accumulate_gas_limit: 1_000_000,
            exports_count: 0,
            payload: payload.to_vec(),
            imports: vec![],
            extrinsics: vec![],
        }],
    }
}
