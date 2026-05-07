pragma foreign_keys = on;

create table if not exists red_pill_runs (
  run_id text primary key,
  target_id text not null,
  target_path text not null,
  generated_at text not null,
  mapper_schema_version text,
  mapper_output_path text,
  status text not null default 'mapped',
  raw_json text not null
);

create table if not exists red_pill_tool_status (
  run_id text not null,
  tool_name text not null,
  available integer not null default 0,
  status text not null default 'unknown',
  path text,
  run_status text,
  raw_json text not null,
  primary key (run_id, tool_name),
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_framework_evidence (
  framework_evidence_id text primary key,
  run_id text not null,
  framework_name text not null,
  confidence real not null default 0,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_dependency_evidence (
  dep_evidence_id text primary key,
  run_id text not null,
  manifest_file text not null,
  dep_name text not null,
  version text not null default '',
  ecosystem text not null default '',
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_library_security (
  lib_sec_id text primary key,
  run_id text not null,
  library_name text not null,
  detected_version text not null default '',
  purpose text not null default '',
  status text not null default 'current',
  issues_json text not null default '[]',
  emitted_flags_json text not null default '[]',
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_observations (
  observation_id text primary key,
  run_id text not null,
  tool text not null,
  kind text not null,
  file text,
  line integer,
  column integer,
  symbol text,
  language text,
  category text,
  render_context text,
  execution_context text,
  confidence real not null default 0,
  snippet text,
  metadata_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_mapping_jobs (
  job_id text primary key,
  run_id text not null,
  job_type text not null,
  target_attack_family text,
  source_observation_id text,
  sink_observation_id text,
  path_provenance_grade text not null default 'unknown',
  preliminary_score real not null default 0,
  preliminary_status text not null default 'unknown',
  persistence text not null default 'unknown',
  transport text not null default 'unknown',
  required_control text,
  source_json text not null,
  flow_json text not null,
  sink_json text not null,
  protection_assessment_json text not null,
  uncertainty_json text not null,
  model_questions_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_job_evidence (
  job_id text not null,
  observation_id text not null,
  evidence_role text not null,
  raw_json text not null,
  primary key (job_id, observation_id, evidence_role),
  foreign key (job_id) references red_pill_mapping_jobs(job_id) on delete cascade
);

create table if not exists red_pill_model_batches (
  batch_id text primary key,
  run_id text not null,
  model_role text not null,
  iteration integer not null,
  status text not null default 'created',
  batch_path text not null,
  record_count integer not null default 0,
  created_at text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_model1_predictions (
  prediction_id text primary key,
  batch_id text,
  run_id text not null,
  job_id text not null,
  iteration integer not null,
  confidence real not null default 0,
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_followup_requests (
  request_id text primary key,
  prediction_id text,
  run_id text not null,
  job_id text not null,
  iteration integer not null,
  request_type text not null,
  status text not null default 'pending',
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_tool_facts (
  fact_id text primary key,
  request_id text,
  run_id text not null,
  job_id text,
  iteration integer not null,
  fact_kind text not null,
  status text not null,
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_model2_verdicts (
  verdict_id text primary key,
  run_id text not null,
  job_id text not null,
  model_name text,
  verdict text not null,
  confidence real not null default 0,
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_hops (
  hop_id text primary key,
  run_id text not null,
  observation_id text,
  kind text not null,
  tool text not null,
  file text,
  line integer,
  symbol text,
  language text,
  route_id text,
  function_scope_id text,
  raw_category text,
  raw_metadata_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_hop_classifications (
  hop_id text primary key,
  run_id text not null,
  classification_version text not null,
  classification_confidence real not null default 0,
  flags_emitted_json text not null,
  flags_required_json text not null,
  flags_invalidated_json text not null,
  flags_observed_json text not null,
  role_flags_json text not null,
  boundary_flags_json text not null,
  stage_flags_json text not null,
  flag_confidence_json text not null,
  uncertainties_json text not null,
  notes text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade,
  foreign key (hop_id) references red_pill_hops(hop_id) on delete cascade
);

create table if not exists red_pill_lineage_semantics (
  lineage_id text primary key,
  run_id text not null,
  family text not null,
  group_key text,
  join_kind text not null,
  join_confidence real not null default 0,
  stage_hop_ids_json text not null,
  stage_roles_json text not null,
  lineage_flags_emitted_json text not null,
  lineage_flags_required_json text not null,
  lineage_flags_invalidated_json text not null,
  upstream_lineage_ids_json text not null,
  downstream_lineage_ids_json text not null,
  analysis_gaps_json text not null,
  fault_line_hop_id text,
  notes text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_backward_candidates (
  candidate_id text primary key,
  run_id text not null,
  sink_hop_id text not null,
  sink_observation_id text,
  family text not null,
  required_flags_json text not null,
  predecessor_hop_ids_json text not null,
  predecessor_kinds_json text not null,
  lineage_ids_json text not null,
  boundary_flags_json text not null,
  predecessor_details_json text not null,
  satisfied_flags_json text not null,
  missing_flags_json text not null,
  contradicted_flags_json text not null,
  provenance_quality text,
  graph_completeness text,
  contract_status text,
  fault_line_hop_id text,
  score real not null default 0,
  tier text not null,
  analysis_notes text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_bubbles (
  bubble_id text primary key,
  run_id text not null,
  job_id text,
  direction text not null,
  anchor_id text not null,
  family text not null,
  node_ids_json text not null,
  lineage_ids_json text not null,
  emitted_flags_json text not null,
  required_flags_json text not null,
  invalidated_flags_json text not null,
  state_confidence real not null default 0,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_intersections (
  intersection_id text primary key,
  run_id text not null,
  job_id text,
  family text not null,
  forward_bubble_id text not null,
  backward_bubble_id text not null,
  meeting_node_ids_json text not null,
  meeting_lineage_ids_json text not null,
  intersection_type text not null,
  required_flags_json text not null,
  satisfied_flags_json text not null,
  missing_flags_json text not null,
  contradicted_flags_json text not null,
  invalidated_after_satisfaction_json text not null,
  fault_line_hop_id text,
  score real not null default 0,
  tier text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_forward_backward_alignments (
  alignment_id text primary key,
  run_id text not null,
  job_id text not null,
  sink_hop_id text,
  status text not null,
  forward_score real not null default 0,
  backward_score real not null default 0,
  shared_hop_ids_json text not null,
  shared_lineage_ids_json text not null,
  shared_function_scopes_json text not null,
  trivial_vectors_json text not null,
  missing_signals_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_function_call_edges (
  edge_id text primary key,
  run_id text not null,
  from_scope text not null,
  to_scope text not null,
  via_symbol text,
  source_hop_id text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_stage_batches (
  stage_batch_id text primary key,
  run_id text not null,
  stage text not null,
  record_count integer not null default 0,
  applied_response_count integer not null default 0,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_stage_records (
  stage_record_id text primary key,
  stage_batch_id text not null,
  run_id text not null,
  stage text not null,
  job_id text not null,
  subject_id text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade,
  foreign key (stage_batch_id) references red_pill_semantic_stage_batches(stage_batch_id) on delete cascade
);

create table if not exists red_pill_ingest_errors (
  error_id text primary key,
  run_id text,
  stage text not null,
  subject_id text,
  error_message text not null,
  raw_json text,
  created_at text not null
);

create table if not exists red_pill_audit_labels (
  label_id integer primary key autoincrement,
  run_id text,
  job_id text,
  intersection_id text,
  reason_code text not null,
  notes text not null default '',
  operator_id text not null default 'human',
  pack_proposed text,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create index if not exists idx_audit_labels_run
  on red_pill_audit_labels(run_id);

create index if not exists idx_audit_labels_reason
  on red_pill_audit_labels(reason_code);
