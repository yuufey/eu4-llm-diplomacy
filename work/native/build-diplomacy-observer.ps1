param(
    [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$Experiment = 'alliance-observer-20261013',
    [switch]$ReasonMetadata,
    [switch]$InformationBattle,
    [switch]$InformationBattleContext,
    [switch]$InformationBattleNaval,
    [switch]$InformationBattleTemplate,
    [switch]$InformationBattleContainer,
    [switch]$InformationBattleWarIdentity,
    [switch]$InformationBattleNativeText,
    [switch]$InformationBattleNativeTitleQuery,
    [switch]$CurrentCountryControl,
    [switch]$BattleGateTrace,
    [switch]$BattleDisplayContext,
    [switch]$DebtQuoteQuery,
    [switch]$BattleNameHandoff,
    [switch]$BattleEndState,
    [switch]$BattleRetreat,
    [switch]$BattleNameSources,
    [switch]$BattleOutcomeText,
    [switch]$BattleOutcomeTail,
    [switch]$CallToArmsObservation,
    [switch]$BattleIndependentLine,
    [switch]$BattleFlagInputs,
    [switch]$SupportRoleContext,
    [switch]$CountryModifierObservation,
    [switch]$CountryModifierRemoval,
    [switch]$CountryModifierExpiry,
    [switch]$RivalObservation,
    [switch]$MacroEventObservation,
    [switch]$MacroSourceObservation,
    [switch]$MissionConditionObservation,
    [switch]$MissionProvinceConditionObservation,
    [switch]$RoyalRecordObservation,
    [switch]$DirectedRecordObservation,
    [switch]$SupportSubjectRecordObservation,
    [switch]$RivalRecordObservation,
    [switch]$SubsidyExpiryObservation,
    [switch]$TruceExpiryObservation,
    [switch]$ClaimExpiryObservation,
    [switch]$LandPromiseObservation
)
$ErrorActionPreference = 'Stop'
if ($LandPromiseObservation) { $ClaimExpiryObservation = $true }
if ($ClaimExpiryObservation) {
    $SubsidyExpiryObservation = $true
    $TruceExpiryObservation = $true
}
if ($SubsidyExpiryObservation) { $RivalRecordObservation = $true }
if ($TruceExpiryObservation) { $RivalRecordObservation = $true }
if ($RivalRecordObservation) { $SupportSubjectRecordObservation = $true }
if ($SupportSubjectRecordObservation) { $DirectedRecordObservation = $true }
if ($DirectedRecordObservation) { $RoyalRecordObservation = $true }
if ($RoyalRecordObservation) { $MissionProvinceConditionObservation = $true }
if ($MissionProvinceConditionObservation) { $MissionConditionObservation = $true }
if ($MissionConditionObservation) { $MacroSourceObservation = $true }
if ($MacroSourceObservation) { $MacroEventObservation = $true }
if ($MacroEventObservation) { $RivalObservation = $true }
if ($RivalObservation) { $CountryModifierExpiry = $true }
if ($CountryModifierExpiry) { $CountryModifierRemoval = $true }
if ($CountryModifierRemoval) { $CountryModifierObservation = $true }
if ($CountryModifierObservation) { $SupportRoleContext = $true }
if ($SupportRoleContext) { $BattleFlagInputs = $true }
if ($BattleFlagInputs) { $BattleIndependentLine = $true }
if ($BattleIndependentLine) { $CallToArmsObservation = $true }
if ($CallToArmsObservation) { $BattleOutcomeTail = $true }
if ($BattleOutcomeTail) { $BattleOutcomeText = $true }
if ($BattleOutcomeText) { $BattleNameSources = $true }
if ($BattleNameSources) { $BattleRetreat = $true }
if ($BattleRetreat) { $BattleEndState = $true }
if ($BattleEndState) { $DebtQuoteQuery = $true }
if ($BattleNameHandoff) { $DebtQuoteQuery = $true }
if ($DebtQuoteQuery) { $BattleDisplayContext = $true }
if ($BattleDisplayContext) { $BattleGateTrace = $true }
if ($BattleGateTrace -and $CurrentCountryControl) {
    throw 'Battle gate trace and current-country control are mutually exclusive.'
}
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'import-local-env.ps1')
Import-ProjectLocalEnv -ProjectRoot $projectRoot
if ($BattleGateTrace) { $InformationBattleNativeTitleQuery = $true }
if ($CurrentCountryControl) { $InformationBattleNativeTitleQuery = $true }
if ($InformationBattleNativeTitleQuery) { $InformationBattleNativeText = $true }
if ($InformationBattleNativeText) { $InformationBattleWarIdentity = $true }
if ($InformationBattleWarIdentity) { $InformationBattleContainer = $true }
if ($InformationBattleContainer) { $InformationBattleTemplate = $true }
if ($InformationBattleTemplate) { $InformationBattleNaval = $true }
if ($InformationBattleNaval) { $InformationBattleContext = $true }
if ($InformationBattleContext) { $InformationBattle = $true }
$outputDirectory = Join-Path $projectRoot ('work\runtime\' + $Experiment)
if (Test-Path -LiteralPath $outputDirectory) { throw 'Use a new experiment directory; existing evidence is immutable.' }
New-Item -ItemType Directory -Path $outputDirectory | Out-Null
$observerVersion = if ($RivalObservation) { 48 } elseif ($CountryModifierExpiry) { 47 } elseif ($CountryModifierRemoval) { 46 } elseif ($CountryModifierObservation) { 45 } elseif ($SupportRoleContext) { 44 } elseif ($BattleFlagInputs) { 43 } elseif ($BattleIndependentLine) { 42 } elseif ($CallToArmsObservation) { 41 } elseif ($BattleOutcomeTail) { 40 } elseif ($BattleOutcomeText) { 39 } elseif ($BattleNameSources) { 38 } elseif ($BattleRetreat) { 37 } elseif ($BattleEndState) { 36 } elseif ($BattleNameHandoff) { 35 } elseif ($DebtQuoteQuery) { 34 } elseif ($BattleDisplayContext) { 33 } elseif ($BattleGateTrace) { 32 } elseif ($CurrentCountryControl) { 31 } elseif ($InformationBattleNativeTitleQuery) { 30 } elseif ($InformationBattleNativeText) { 29 } elseif ($InformationBattleWarIdentity) { 28 } elseif ($InformationBattleContainer) { 27 } elseif ($InformationBattleTemplate) { 26 } elseif ($InformationBattleNaval) { 25 } elseif ($InformationBattleContext) { 24 } elseif ($InformationBattle) { 23 } else { 22 }
if ($MacroEventObservation) { $observerVersion = 51 }
if ($MacroSourceObservation) { $observerVersion = 55 }
if ($MissionConditionObservation) { $observerVersion = 56 }
if ($MissionProvinceConditionObservation) { $observerVersion = 57 }
if ($RoyalRecordObservation) { $observerVersion = 58 }
if ($DirectedRecordObservation) { $observerVersion = 59 }
if ($SupportSubjectRecordObservation) { $observerVersion = 60 }
if ($RivalRecordObservation) { $observerVersion = 61 }
if ($SubsidyExpiryObservation) { $observerVersion = 62 }
if ($TruceExpiryObservation) { $observerVersion = 62 }
if ($ClaimExpiryObservation) { $observerVersion = 63 }
if ($LandPromiseObservation) { $observerVersion = 64 }
$dllName = 'eu4_bridge_diplomacy_observer_v' + $observerVersion + '.dll'
$dll = Join-Path $outputDirectory $dllName
$rootSource = Join-Path $PSScriptRoot 'diplomacy-observer-v10.cpp'
$frameStub = Join-Path $PSScriptRoot 'frame_stub.S'
$arguments = @('-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-fno-rtti',
    '-shared', '-static-libgcc', '-static-libstdc++', '-Wl,--no-insert-timestamp',
    '-o', $dll, $rootSource, $frameStub)
if ($InformationBattle) {
    $arguments += (Join-Path $PSScriptRoot 'information-battle-entry-stub.S')
    $arguments += '-ladvapi32'
    $arguments = @('-DBRIDGE_INFORMATION_BATTLE=1') + $arguments
}
if ($ReasonMetadata) { $arguments = @('-DBRIDGE_ALLIANCE_REASON_METADATA=1') + $arguments }
if ($InformationBattleContext) { $arguments = @('-DINFORMATION_BATTLE_CONTEXT=1') + $arguments }
if ($InformationBattleNaval) { $arguments = @('-DINFORMATION_BATTLE_NAVAL=1') + $arguments }
if ($InformationBattleTemplate) { $arguments = @('-DINFORMATION_BATTLE_TEMPLATE=1') + $arguments }
if ($InformationBattleContainer) { $arguments = @('-DINFORMATION_BATTLE_CONTAINER=1') + $arguments }
if ($InformationBattleWarIdentity) { $arguments = @('-DINFORMATION_BATTLE_WAR_IDENTITY=1') + $arguments }
if ($InformationBattleNativeText) {
    $arguments += (Join-Path $PSScriptRoot 'information-battle-line1-observer-stub.S')
    $arguments = @('-DINFORMATION_BATTLE_NATIVE_TEXT=1') + $arguments
}
if ($InformationBattleNativeTitleQuery) {
    $arguments = @('-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1') + $arguments
}
if ($BattleGateTrace) {
    $arguments = @('-DINFORMATION_BATTLE_GATE_TRACE=1') + $arguments
}
if ($BattleDisplayContext) {
    $arguments = @('-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1') + $arguments
}
if ($DebtQuoteQuery) {
    $arguments = @('-DBRIDGE_DEBT_QUOTE_QUERY=1') + $arguments
}
if ($BattleNameHandoff) {
    $arguments += (Join-Path $PSScriptRoot 'information-battle-name-handoff-observer-stub.S')
    $arguments = @('-DINFORMATION_BATTLE_NAME_HANDOFF=1') + $arguments
}
if ($BattleEndState) {
    $arguments = @('-DINFORMATION_BATTLE_END_STATE=1') + $arguments
}
if ($BattleRetreat) {
    $arguments = @('-DINFORMATION_BATTLE_RETREAT=1') + $arguments
}
if ($BattleNameSources) {
    $arguments = @('-DINFORMATION_BATTLE_NAME_SOURCES=1', '-DINFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE=1') + $arguments
}
if ($BattleOutcomeText) {
    $arguments = @('-DINFORMATION_BATTLE_OUTCOME_TEXT=1') + $arguments
}
if ($BattleOutcomeTail) {
    $arguments = @('-DINFORMATION_BATTLE_OUTCOME_TAIL=1') + $arguments
}
if ($CallToArmsObservation) {
    $arguments = @('-DBRIDGE_CALL_TO_ARMS_OBSERVATION=1') + $arguments
}
if ($BattleIndependentLine) {
    $arguments = @('-DINFORMATION_BATTLE_INDEPENDENT_LINE=1') + $arguments
    if ($BattleFlagInputs) { $arguments = @('-DINFORMATION_BATTLE_FLAG_INPUTS=1') + $arguments }
    $arguments = $arguments | ForEach-Object { if ($_ -eq '-std=c++17') { '-std=c++20' } else { $_ } }
    $arguments += @('-I', (Join-Path $projectRoot 'work\candidates\information-battle-format-input-1374'))
}
if ($CurrentCountryControl) {
    $arguments = @('-DBRIDGE_CURRENT_COUNTRY_CONTROL=1') + $arguments
}
if ($SupportRoleContext) { $arguments = @('-DBRIDGE_SUPPORT_ROLE_CONTEXT=1') + $arguments }
if ($CountryModifierObservation) { $arguments = @('-DBRIDGE_COUNTRY_MODIFIER_OBSERVATION=1') + $arguments }
if ($CountryModifierRemoval) { $arguments = @('-DBRIDGE_COUNTRY_MODIFIER_REMOVAL=1') + $arguments }
if ($CountryModifierExpiry) {
    $arguments = @('-DBRIDGE_COUNTRY_MODIFIER_EXPIRY=1') + $arguments
    $arguments += (Join-Path $PSScriptRoot 'information-country-modifier-expiry-entry.S')
}
if ($RivalObservation) { $arguments = @('-DBRIDGE_RIVAL_OBSERVATION=1') + $arguments }
if ($MacroEventObservation) {
    $arguments = @('-DBRIDGE_WAR_DECLARATION_OBSERVATION=1', '-DBRIDGE_RELATION_OBSERVATION=1',
        '-DBRIDGE_MISSION_COMPLETION_OBSERVATION=1') + $arguments
}
if ($MacroSourceObservation) {
    $arguments = @('-DBRIDGE_MISSION_AVAILABILITY_OBSERVATION=1',
        '-DBRIDGE_MISSION_COMPLETED_SET_OBSERVATION=1', '-DBRIDGE_ALLIANCE_RECORD_OBSERVATION=1') + $arguments
}
if ($MissionConditionObservation) {
    $arguments = @('-DBRIDGE_MISSION_CONDITION_OBSERVATION=1') + $arguments
}
if ($MissionProvinceConditionObservation) {
    $arguments = @('-DBRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION=1') + $arguments
}
if ($RoyalRecordObservation) {
    $arguments = @('-DBRIDGE_ROYAL_RECORD_OBSERVATION=1') + $arguments
}
if ($DirectedRecordObservation) {
    $arguments = @('-DBRIDGE_DIRECTED_RECORD_OBSERVATION=1') + $arguments
}
if ($SupportSubjectRecordObservation) {
    $arguments = @('-DBRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION=1') + $arguments
}
if ($RivalRecordObservation) {
    $arguments = @('-DBRIDGE_RIVAL_RECORD_OBSERVATION=1') + $arguments
}
if ($SubsidyExpiryObservation) {
    $arguments = @('-DBRIDGE_SUBSIDY_EXPIRY_OBSERVATION=1') + $arguments
}
if ($TruceExpiryObservation) {
    $arguments = @('-DBRIDGE_TRUCE_EXPIRY_OBSERVATION=1') + $arguments
}
if ($ClaimExpiryObservation) {
    $arguments = @('-DBRIDGE_CLAIM_EXPIRY_OBSERVATION=1') + $arguments
}
if ($LandPromiseObservation) {
    $arguments = @('-DBRIDGE_LAND_PROMISE_OBSERVATION=1') + $arguments
}
& (Get-ProjectLocalValue -Name 'EU4_CXX') @arguments
if ($LASTEXITCODE -ne 0) { throw 'Observer build failed; directory retained as failed evidence.' }
$sourceNames = @('diplomacy-observer-v10.cpp','alliance-query.inc','favor-state.inc','gift-influence-state.inc','insult-query.inc','rival-query.inc','vassal-query.inc','declarewar-query.inc','peace-context-query.inc','peace-empty-offer-query.inc','peace-offer-evaluation-query.inc','peace-money-query.inc','peace-war-context-query.inc','live-war-score-query.inc','live-war-score-query.h','peace-payload.h','peace-native-payload.inc','peace-province-candidates.inc','peace-province-selection.inc','declarewar-payload.h','declarewar-native-payload.inc','declarewar-execution-preflight.inc','declarewar-execution-state.inc','declarewar-cost-query.inc','declarewar-candidates.inc','vassal-test-context.inc','vassal-test-context-script.h','vassal-inbound-test-context.inc','vassal-inbound-test-context-script.h','rival-authority.inc','rival-command-observer.inc','rival-execution.inc','rival-command-authority.h','rival-command-wire.h','alliance-reason-metadata.inc','alliance-reason-metadata-bind.inc','alliance-reason-key-branch.h','alliance-reason-row.h','alliance-lifecycle.inc','alliance-entry-observer.inc','alliance-protocol-observer.inc','alliance-transport.inc','alliance-authority-ledger.h','alliance-execution-wire.h','alliance-inbound-response-wire.h','alliance-inbound-inspection-event.h','alliance-pending-membership.h','alliance-inbound.inc','inbound-pending-recovery.inc','alliance-execution.inc','entry-patch-transaction.inc','control-probe.cpp','automated-control.inc','popup-control.inc','frame_stub.S')
$sourceNames += @('peace-payload-ref.h','peace-action-native-payload.inc','peace-lifecycle-hooks.inc','peace-execution-preflight.inc','peace-handler-authority.inc')
$sourceNames += @('peace-war-side-members.inc')
$sourceNames += @('information-war-registry.h')
$sourceNames += @('territorial-interest-query.inc')
$sourceNames += @('peace-execution-wire.h','peace-execution.inc','peace-inbound-context.inc')
$sourceNames += @('peace-receiver-observer.inc')
$sourceNames += @('peace-wrapper-rule-query.inc')
$sourceNames += @('peace-effects.h','peace-effect-state.inc')
$sourceNames += @('peace-core-effects.inc')
$sourceNames += @('peace-subject-effects.inc','peace-country-effects.inc')
$sourceNames += @('peace-special-selection.inc','peace-special-state.inc')
$sourceNames += @('religion-war-context.inc','religion-war-context-script.h')
$sourceNames += @('peace-reparations-selection.inc','peace-reparations-state.inc','peace-annul-selection.inc')
$sourceNames += @('peace-core-candidates.inc','peace-subject-candidates.inc','peace-country-candidates.inc','peace-annex-selection.inc','peace-selected-rules.inc')
$sourceNames += @('declarewar-details-query.inc')
$sourceNames += @('declarewar-peace-options-query.inc')
$sourceNames += @('declarewar-selection.h','declarewar-participants-query.inc')
$sourceNames += @('declarewar-force-sides.inc','declarewar-forces-query.inc')
$sourceNames += @('peace-consequences-query.inc','peace-coalition-capture.inc')
$sourceNames += @('peace-overextension-query.inc')
$sourceNames += @('peace-justification-query.inc')
if ($InformationBattle) {
    $sourceNames += @(
        'information-battle-observer.inc',
        'information-battle-entry-stub.S',
        'information-battle-entry-plan.h',
        'information-battle-owned-result.h',
        'information-battle-owned-summary.h',
        'information-battle-buffer.h',
        'information-battle-drain.h',
        'information-battle-wire.h',
        'information-battle-log-writer.h',
        'information-battle-observation-wire.h',
        'information-battle-fragment.h'
    )
}
if ($InformationBattleContext) {
    $sourceNames += @('information-battle-owned-context.h', 'information-battle-context-wire.h')
}
if ($InformationBattleNaval) {
    $sourceNames += @('information-battle-owned-naval.h', 'information-battle-naval-wire.h')
}
if ($InformationBattleTemplate) {
    $sourceNames += @('information-battle-owned-template.h', 'information-battle-template-wire.h', 'information-battle-message-entry-plan.h')
}
if ($InformationBattleWarIdentity) {
    $sourceNames += @('information-battle-war-binding.h', 'information-battle-war-identity-wire.h')
}
if ($InformationBattleNativeText) {
    $sourceNames += @(
        'information-battle-owned-native-text.h',
        'information-battle-native-text-wire.h',
        'information-battle-line1-entry-plan.h',
        'information-battle-line1-observer-stub.S'
    )
}
if ($InformationBattleNativeTitleQuery) {
    $sourceNames += @(
        'information-battle-owned-title-query.h',
        'information-battle-title-query-plan.h'
    )
}
if ($BattleGateTrace) {
    $sourceNames += @(
        'information-battle-owned-gate-inputs.h',
        'information-battle-gate-trace.h',
        'information-battle-gate-marker-entry-plan.h'
    )
}
if ($BattleDisplayContext) {
    $sourceNames += @(
        'information-battle-display-context-layout.h',
        'information-battle-owned-display-context.h',
        'information-battle-display-context-wire.h'
    )
}
if ($DebtQuoteQuery) {
    $sourceNames += @('debt-quote-query.inc', 'debt-quote-native-guards.h')
}
if ($BattleNameHandoff) {
    $sourceNames += @('information-battle-name-handoff-observer-stub.S',
        'information-battle-name-handoff-entry-plan.h','information-battle-owned-name-handoff.h',
        'information-battle-name-handoff-wire.h','information-battle-name-handoff-callsite-guards.inc')
}
if ($BattleEndState) {
    $sourceNames += @('information-battle-owned-end-state.h','information-battle-end-state-wire.h')
    if (-not $BattleNameHandoff) {
        $sourceNames += @('information-battle-name-handoff-wire.h','information-battle-owned-name-handoff.h')
    }
}
if ($BattleRetreat) {
    $sourceNames += @('information-battle-retreat-wire.h','information-battle-owned-retreat.h',
        'information-battle-retreat-entry-plan.h','information-battle-retreat-observer.inc')
}
if ($BattleNameSources) {
    $sourceNames += @('information-battle-owned-name-sources.h','information-battle-owned-name-prefix.h',
        'information-battle-name-sources-wire.h')
}
if ($BattleOutcomeText) {
    $sourceNames += @('information-battle-owned-outcome-text.h','information-battle-outcome-text-wire.h',
        'information-battle-outcome-text-record.h')
}
if ($BattleOutcomeTail) {
    $sourceNames += @('information-battle-owned-outcome-tail.h','information-battle-outcome-tail-wire.h',
        'information-battle-outcome-tail-record.h')
}
if ($CallToArmsObservation) {
    $sourceNames += @('call-to-arms-observer.inc')
}
if ($CurrentCountryControl) {
    $sourceNames += @(
        'information-current-country-control.inc',
        'information-current-country-control-plan.h',
        'information-current-country-control-policy.h'
    )
}
if ($BattleIndependentLine) {
    $sourceNames += @('information-battle-independent-line-wire.h','information-battle-owned-independent-line.h',
        'information-battle-independent-line-plan.h')
}
if ($BattleFlagInputs) {
    $sourceNames += @('information-battle-flag-input-wire.h','information-battle-owned-flag-inputs.h')
}
if ($SupportRoleContext) {
    $sourceNames += @('support-role-state.h')
}
if ($CountryModifierObservation) {
    $sourceNames += @('information-country-modifier-add.h', 'information-country-modifier-entry-plan.h',
        'information-country-modifier-observer.inc')
}
if ($CountryModifierRemoval) {
    $sourceNames += @('information-country-modifier-remove.h', 'information-country-modifier-remove-entry-plan.h')
}
if ($CountryModifierExpiry) {
    $sourceNames += @('information-country-modifier-expiry.h', 'information-country-modifier-expiry-entry.S')
}
if ($RivalObservation) {
    $sourceNames += @('information-rival-change.h', 'information-rival-observer.inc')
}
if ($MacroEventObservation) {
    $sourceNames += @('information-war-declaration.h', 'information-war-declaration-observer.inc',
        'information-relation-change.h', 'information-relation-observer.inc',
        'information-mission-completion.h', 'information-mission-observer.inc')
}
if ($MacroSourceObservation) {
    $sourceNames += @('information-mission-availability.h', 'information-mission-availability-entry-plan.h',
        'information-mission-availability-observer.inc', 'information-mission-completed-set-entry-plan.h',
        'information-mission-completed-set-observer.inc', 'information-alliance-record-entry-plan.h',
        'information-alliance-record-observer.inc')
}
if ($MissionConditionObservation) {
    $sourceNames += @('information-mission-conditions.h', 'information-mission-condition-entry-plan.h',
        'information-mission-condition-observer.inc')
}
if ($MissionProvinceConditionObservation) {
    $sourceNames += @('information-mission-province-conditions.h', 'information-mission-province-entry-plan.h',
        'information-mission-province-observer.inc')
}
if ($RoyalRecordObservation) {
    $sourceNames += @('information-royal-record-entry-plan.h', 'information-royal-record-observer.inc')
}
if ($DirectedRecordObservation) {
    $sourceNames += @('information-directed-record-entry-plan.h', 'information-directed-record-observer.inc')
}
if ($SupportSubjectRecordObservation) {
    $sourceNames += @('information-support-subject-record-entry-plan.h',
        'information-support-subject-record-observer.inc')
}
if ($RivalRecordObservation) {
    $sourceNames += @('information-rival-record-entry-plan.h',
        'information-rival-record-observer.inc')
}
if ($SubsidyExpiryObservation) {
    $sourceNames += @('information-subsidy-expiry.h', 'information-subsidy-expiry-entry-plan.h',
        'information-subsidy-expiry-native-guards.h', 'information-subsidy-expiry-observer.inc')
}
if ($TruceExpiryObservation) {
    $sourceNames += @('information-truce-expiry.h', 'information-truce-expiry-entry-plan.h',
        'information-truce-expiry-native-guards.h', 'information-truce-expiry-observer.inc')
}
if ($ClaimExpiryObservation) {
    $sourceNames += @('information-claim-expiry.h', 'information-claim-expiry-entry-plan.h',
        'information-claim-expiry-native-guards.h', 'information-claim-expiry-observer.inc')
}
if ($LandPromiseObservation) {
    $sourceNames += @('information-land-promise.h', 'information-land-promise-native-guards.h',
        'information-land-promise-observer.inc')
}
$sources = foreach ($name in $sourceNames) {
    $source = Join-Path $PSScriptRoot $name
    Copy-Item -LiteralPath $source -Destination (Join-Path $outputDirectory $name)
    [ordered]@{ name = $name; sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() }
}
if ($BattleIndependentLine) {
    $candidateRoot = Join-Path $projectRoot 'work\candidates\information-battle-format-input-1374'
    foreach ($name in @('format_input_builder.h','format_expansion_plan.h')) {
        $source = Join-Path $candidateRoot $name
        Copy-Item -LiteralPath $source -Destination (Join-Path $outputDirectory $name)
        $sources += [ordered]@{ name = $name; sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
}
$game = Join-Path (Get-ProjectLocalValue -Name 'EU4_GAME_ROOT') 'eu4.exe'
$manifest = [ordered]@{ version = $observerVersion; experiment_id = $Experiment; compiled = $true; runtime_verified = $false; reason_metadata_requested = [bool]$ReasonMetadata
    game_sha256 = (Get-FileHash -LiteralPath $game -Algorithm SHA256).Hash.ToLowerInvariant()
    dll_sha256 = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()
    dll = $dll; sources = @($sources); compiler_arguments = $arguments }
$manifest.native_war_participants_query = $true
$manifest.native_territorial_interest_query = $true
$manifest.native_territorial_interest_query_wire = 23
if ($BattleEndState) {
    $manifest.information_battle_end_state = $true
    $manifest.information_battle_end_state_wire = 9
    $manifest.information_battle_end_state_complete = $false
}
if ($BattleRetreat) {
    $manifest.information_battle_retreat = $true
    $manifest.information_battle_retreat_wire = 10
    $manifest.information_battle_retreat_stage = 'regular_battle_end_unit_path_callback'
    $manifest.information_battle_retreat_complete = $false
    $manifest.information_battle_retreat_unit_removal = $true
    $manifest.information_battle_retreat_max_extension_version = 2
}
if ($BattleNameHandoff) {
    $manifest.information_battle_name_handoff = $true
    $manifest.information_battle_name_handoff_wire = 8
    $manifest.information_battle_name_handoff_stage = 'before_pair_move'
    $manifest.information_battle_name_handoff_complete = $false
}
if ($InformationBattle) { $manifest.information_battle_research_lifecycle = $true }
if ($InformationBattleContext) {
    $manifest.information_battle_context_wire = 2
    $manifest.information_battle_owned_context = $true
}
if ($InformationBattleNaval) {
    $manifest.information_battle_naval_wire = 3
    $manifest.information_battle_owned_naval = $true
}
if ($InformationBattleTemplate) {
    $manifest.information_battle_template_wire = 4
    $manifest.information_battle_owned_template = $true
    $manifest.information_battle_message_scope = $true
}
if ($InformationBattleContainer) {
    $manifest.information_battle_formatter_container = $true
    $manifest.information_battle_template_extensions = @(1, 2)
}
if ($InformationBattleWarIdentity) {
    $manifest.information_battle_war_identity = $true
    $manifest.information_battle_war_identity_wire = 5
    $manifest.information_battle_war_identity_scope = 'observer_session'
    $manifest.information_battle_war_identity_read_only = $true
    $manifest.information_battle_war_identity_complete = $false
}
if ($InformationBattleNativeText) {
    $manifest.information_battle_native_text = $true
    $manifest.information_battle_native_text_wire = 6
    $manifest.information_battle_native_text_scope = 'observer_session'
    $manifest.information_battle_native_text_read_only = $true
    $manifest.information_battle_native_text_complete = $false
}
if ($InformationBattleNativeTitleQuery) {
    $manifest.information_battle_native_title_query = -not [bool]$BattleNameSources
    $manifest.information_battle_native_title_query_mode = if ($BattleNameSources) { 'cached_sources_no_helper_invoke' } else { 'native_helper_owned_output' }
    $manifest.information_battle_native_title_query_wire = 6
    $manifest.information_battle_native_title_query_complete = $false
}
if ($BattleNameSources) {
    $manifest.information_battle_name_sources = $true
    $manifest.information_battle_name_sources_wire = 11
    $manifest.information_battle_name_sources_stage = 'entry_before_client_gate'
    $manifest.information_battle_name_sources_read_only = $true
    $manifest.information_battle_name_sources_complete = $false
}
if ($BattleOutcomeText) {
    $manifest.information_battle_outcome_text = $true
    $manifest.information_battle_outcome_text_wire = 12
    $manifest.information_battle_outcome_text_stage = 'entry_before_client_gate'
    $manifest.information_battle_outcome_text_read_only = $true
    $manifest.information_battle_outcome_text_complete = $false
}
if ($BattleOutcomeTail) {
    $manifest.information_battle_outcome_tail = $true
    $manifest.information_battle_outcome_tail_wire = 13
    $manifest.information_battle_outcome_tail_stage = 'entry_before_client_gate'
    $manifest.information_battle_outcome_tail_read_only = $true
    $manifest.information_battle_outcome_tail_complete = $false
}
if ($CallToArmsObservation) {
    $manifest.call_to_arms_observation = $true
    $manifest.call_to_arms_ai_response_held = $false
    $manifest.call_to_arms_execution = $false
}
if ($BattleGateTrace) {
    $manifest.information_battle_gate_trace = $true
    $manifest.information_battle_gate_trace_protocol = 'EU4-BATTLE-GATE-TRACE/1'
    $manifest.information_battle_gate_trace_runtime_verified = $false
}
if ($BattleDisplayContext) {
    $manifest.information_battle_display_context = $true
    $manifest.information_battle_display_context_wire = 7
    $manifest.information_battle_display_context_scope = 'same_battle_event'
    $manifest.information_battle_display_context_stage = 'router_scope_exit'
    $manifest.information_battle_display_context_read_only = $true
    $manifest.information_battle_display_context_complete = $false
}
if ($DebtQuoteQuery) {
    $manifest.information_debt_quote_query = $true
    $manifest.information_debt_quote_query_wire = 1
    $manifest.information_debt_quote_read_only = $true
    $manifest.information_debt_quote_fp_context = $true
}
if ($CurrentCountryControl) {
    $manifest.current_country_control_test_only = $true
    $manifest.current_country_control_protocol = 'EU4COUNTRY1'
    $manifest.current_country_control_entry_rva = '0x779360'
}
if ($BattleIndependentLine) {
    $manifest.information_battle_independent_line = $true
    $manifest.information_battle_independent_line_wire = 14
    $manifest.information_battle_independent_line_native_formatter = $true
    $manifest.information_battle_independent_line_stage = 'router_scope_exit'
    $manifest.information_battle_independent_line_actual_popup = $false
}
if ($BattleFlagInputs) {
    $manifest.information_battle_flag_inputs = $true
    $manifest.information_battle_flag_inputs_wire = 15
    $manifest.information_battle_flag_inputs_stage = 'formatter_container_before_cleanup'
    $manifest.information_battle_flag_inputs_actual_widget = $false
}
if ($SupportRoleContext) {
    $manifest.native_support_role_context = $true
    $manifest.native_support_role_context_read_only = $true
    $manifest.native_support_role_context_fields = @('support_roles_readable','support_actor_is_subject','support_recipient_is_subject')
}
if ($CountryModifierObservation) {
    $manifest.native_country_modifier_add_observation = $true
    $manifest.native_country_modifier_add_wire = 1
    $manifest.native_country_modifier_scope = 'FRA_direct_temporary_records'
}
if ($CountryModifierRemoval) {
    $manifest.native_country_modifier_remove_observation = $true
    $manifest.native_country_modifier_remove_wire = 1
}
if ($CountryModifierExpiry) {
    $manifest.native_country_modifier_expiry_observation = $true
    $manifest.native_country_modifier_expiry_wire = 1
}
if ($RivalObservation) {
    $manifest.native_rival_change_observation = $true
    $manifest.native_rival_change_wire = 1
    $manifest.native_rival_change_scope = 'FRA_actor_target_or_old_rival_at_three_country_command_entries'
}
if ($MacroEventObservation) {
    $manifest.native_war_declaration_observation = $true
    $manifest.native_war_declaration_wire = 1
    $manifest.native_war_declaration_scope = 'FRA_member_in_new_declared_pair_war'
    $manifest.native_relation_change_observation = $true
    $manifest.native_relation_change_wire = 1
    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_returns'
    $manifest.native_mission_completion_observation = $true
    $manifest.native_mission_completion_wire = 1
    $manifest.native_mission_completion_scope = 'FRA_completed_transition_at_native_mission_command_return'
}
if ($MacroSourceObservation) {
    $manifest.native_relation_change_wire = 2
    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_or_alliance_record_returns'
    $manifest.native_alliance_record_observation = $true
    $manifest.native_mission_completion_wire = 2
    $manifest.native_mission_completion_scope = 'FRA_completed_set_insert_at_command_or_effect_return'
    $manifest.native_mission_completed_set_observation = $true
    $manifest.native_mission_availability_observation = $true
    $manifest.native_mission_availability_wire = 1
    $manifest.native_mission_availability_scope = 'FRA_native_task_eligibility_return'
}
if ($MissionConditionObservation) {
    $manifest.native_mission_condition_observation = $true
    $manifest.native_mission_condition_wire = 1
    $manifest.native_mission_condition_scope = 'FRA_root_conjunction_child_returns'
    $manifest.prototype_only = $false
    $manifest.formal_installation_admitted = $true
}
if ($MissionProvinceConditionObservation) {
    $manifest.native_mission_condition_wire = 2
    $manifest.native_mission_condition_scope = 'FRA_root_and_direct_area_province_holding_returns'
    $manifest.native_mission_province_condition_observation = $true
    $manifest.prototype_only = $false
    $manifest.formal_installation_admitted = $true
}
if ($RoyalRecordObservation) {
    $manifest.native_relation_change_wire = 3
    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns'
    $manifest.native_royal_record_observation = $true
    $manifest.prototype_only = $false
    $manifest.formal_installation_admitted = $true
}
if ($DirectedRecordObservation) {
    $manifest.native_relation_change_wire = 4
    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns'
    $manifest.native_directed_record_observation = $true
    $manifest.prototype_only = $false
    $manifest.formal_installation_admitted = $true
}
if ($SupportSubjectRecordObservation) {
    $manifest.native_relation_change_wire = 5
    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_or_six_family_record_returns'
    $manifest.native_support_subject_record_observation = $true
    $manifest.prototype_only = $false
    $manifest.formal_installation_admitted = $true
}
if ($RivalRecordObservation) {
    $manifest.native_rival_change_wire = 2
    $manifest.native_rival_change_scope = 'FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns'
    $manifest.native_rival_record_observation = $true
    $manifest.native_rival_record_count_basis = 'active_nonretired_nodes'
    $manifest.prototype_only = $false
    $manifest.formal_installation_admitted = $true
}
if ($SubsidyExpiryObservation) {
    $manifest.native_subsidy_expiry_observation = $true
    $manifest.native_subsidy_expiry_wire = 1
    $manifest.native_subsidy_expiry_scope = 'FRA_payer_or_recipient_at_subsidy_expiry_remove_return'
}
if ($TruceExpiryObservation) {
    $manifest.native_truce_expiry_observation = $true
    $manifest.native_truce_expiry_wire = 1
    $manifest.native_truce_expiry_scope = 'FRA_actor_or_recipient_directional_direct_truce_expiry_returns'
}
if ($ClaimExpiryObservation) {
    $manifest.native_claim_expiry_observation = $true
    $manifest.native_claim_expiry_wire = 1
    $manifest.native_claim_expiry_scope = 'FRA_claimant_or_current_owner_at_native_claim_expiry_remove_return'
}
if ($LandPromiseObservation) {
    $manifest.native_land_promise_observation = $true
    $manifest.native_land_promise_wire = 1
    $manifest.native_land_promise_scope = 'FRA_member_in_observed_promise_war'
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputDirectory 'build-manifest.json') -Encoding UTF8
Get-FileHash -LiteralPath $dll -Algorithm SHA256
