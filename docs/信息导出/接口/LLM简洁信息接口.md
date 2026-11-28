# LLM简洁信息接口

信息查询、结果回读、结果列表和订阅交付默认返回简洁业务数据。数值已按来源定义的缩放比例换算，金币统一使用ducats。`previous_month_recurring`表示上一月经常收入、经常支出和结余。无可用值返回`null`，零和false保留其值。

`F02`、`G03`、`G06`、`W01`–`W03`、`T03`–`T05` 和 `R05` 的简洁结果在有缺值时附带 `missing_fields`，按字段给出状态和原因。例如 `invisible` 表示可见性条件未满足，`unsupported` 表示当前来源未实现该查询，`unavailable` 表示当前无法采集。已确认的空列表仍用 `[]` 表示。

`information_query`接受现有查询集合或报告编号。

N01的国库、月度账目及贷款查询可省略`parameters`，例如以下调用。`reference_recipient`为可选兼容参数，显式提供时可在国库缓存不可用后使用原国家对预览回退。

```json
{"request_id": "finance-read-001", "queries": [{"topic": "N01", "object": {"type": "country", "country": "FRA"}, "fields": ["treasury", "loan_summary"]}]}
```

逐笔查询 `loans` 时，简洁结果增加可读的 `due_date` 和从本次观测日到到期日的 `days_until_due`。当天到期为零，已过期为负数。同时选择 `loans` 和 `loan_summary` 时分别返回明细与汇总。单独选择 `loan_summary` 时，汇总仍放在 `loans` 下。

`T03.outgoing_value` 的 `total_ducats` 是节点流出总额，`routes` 中每项的 `ducats` 是流向指定 `node_id` 的分项金额。`T04.shares` 返回观察国的原生份额缓存。`T04.power_share_percent` 使用同次采集的观察国贸易力除以节点总贸易力，输出百分比。总贸易力为零或缺少有效输入时，该百分比返回空值。

`G06.provinces` 从指定国家的当前领土中查找观察国已发现的省份。可按货物 `resource`（资源键或已取得的本地名称）、贸易节点 `trade_node`、是否有贸易中心 `center_of_trade` 或是否为河口 `river_estuary` 筛选。贸易节点和河口筛选需要开启 `--static-game-data`。

```json
{"request_id": "serbian-gold", "queries": [{"topic": "G06", "object": {"type": "country", "country": "SER"}, "fields": ["provinces"], "parameters": {"resource": "gold", "limit": 12}}]}
```

每次最多核对 24 个候选。河口筛选还需要逐省读取修正，每页最多核对 8 个候选。即使当前页没有匹配，仍可将 `next_offset` 作为下次请求的 `offset` 继续查询。各页按查询时的当前领土读取，分页期间领土变化会影响结果。`unknown_candidates` 是本页因可见性、所有权或所选筛选字段未能核实而跳过的候选数。

财政输出示例采用历史实采值。

```json
{
  "result_id": "result-4140c10d879c4dac9e53c6abf13c4fd0",
  "items": [{
    "country": "FRA",
    "treasury": 84.730,
    "previous_month_recurring": {"income": 29.198, "expenses": 31.253, "balance": -2.055},
    "loans": {"count": 4, "principal": 512}
  }]
}
```

每个查询对应一个items条目，对象身份与所选字段直接列在条目中。查询的原始数据、内部来源、采集日期差异、诊断和验证备注保存在完整记录中。使用以下参数调用`information_get_result`可取完整记录。

```json
{"result_id": "result-4140c10d879c4dac9e53c6abf13c4fd0", "view": "full"}
```

`information_query`、`information_get_result`、`information_list_results`、`information_tick`支持`view`参数，可取`concise`或`full`，默认`concise`。旧报告的raw、brief、full配置仍可读取，其面向LLM的默认返回统一为简洁视图。完整结果按原格式存储。

`information_discover`默认返回主题编号、标题、接入状态与字段名列表。可使用以下参数查看一个主题的完整对象与参数定义。

```json
{"topics": ["N01"], "view": "full"}
```

订阅输出适配器接收同样的简洁结果。事件中的业务内容随结果返回，完整事件记录可通过结果编号回读。服务管理工具用于显式配置与诊断。

C01的`game_date`、事件元数据的`game_date`和C04所选字段`event_date`在简洁视图中采用`1470.11.30`这样的游戏日期。完整视图保留原生时钟值。

## 本国修正

N07与N08按`modifiers`逐条返回所选内容，每条包含`modifier_id`。N07的`effects`使用当前游戏及启用模组配置中的效果名与数值，例如`diplomatic_upkeep: 1`、`nobles_loyalty_modifier: 0.1`。比率沿用游戏配置的表达，0.1表示10%。这些值描述该项直接国家修正的定义效果。

N08的`start_date`和`end_date`采用可读游戏日期，`remaining_days`以天计。无已知起始日期或无固定结束日期时，相应值为`null`。各条目的未知值随该条目保留。

`duration_type`为`ruler_modifier`时表示该修正关联当前统治者，已知的固定到期日同时通过`end_date`提供。普通固定期限修正为`fixed_term`，无固定到期日为`no_fixed_end_date`。

历史记录若只有原生效果索引与数值，简洁视图中的`effects`为`null`。完整视图保留原生记录及具名效果的配置依据。

C04的修正新增、移除和自然到期通知通过`event_payload`提供`country`、`modifier_id`、`change`及已知的`start_date`、`end_date`。日期采用游戏日历，无已知起始日期或无固定结束日期时为`null`。原生标志及原始时钟值保存在完整视图中。

## 盟友参战意愿

D04的 `allies` 按国家列出所选宣战方案的参战候选，包含攻守双方的盟友及自动参战国家。`side` 表示attacker或defender，`automatic` 表示是否自动参战。`willingness.score` 为原生接受总分，`threshold` 为接受门槛，`reasons` 保留各原因的数值和文字。`land_promise_available` 表示该候选可否在本方案中获得土地许诺，参战意愿仍使用对应方案的分数判断。

查询按现有 `parameters.selection` 传入具体CB、战争目标及参战选择。以下为当前实读中的SAV条目，原因列表节选两项。

```json
{
  "country": "SAV",
  "side": "attacker",
  "automatic": false,
  "willingness": {"score": -1037, "threshold": 1},
  "reasons": [
    {"value": -1000, "text": "正在打另一场战争："},
    {"value": -40, "text": "萨伏依负债90¤："}
  ],
  "land_promise_available": true
}
```

按所选字段返回对应内容。`favor_requirement` 可提供 `{"without_land_promise": 10}`，表示使用人情召集可选盟友、未许诺土地时的生效配置门槛。该规则用于比较人情与土地许诺两种方案，旧原生或录制结果已有的人情值继续优先读取。完整视图保留原生原因和采集范围，旧记录的平面字段继续按原结构读取。

D03的 `automatic_participants` 提供自动参战候选，`allies` 和 `co_belligerents` 提供本次具体方案中已选的召盟及共同交战国家。这些行带有所属一侧及选中状态。D05的 `attacker_forces` 和 `defender_forces` 提供原生预览实际计入的国家、步骑炮人数及后备人力，随所选方案重新读取。

D03的 `guarantors` 按候选国向关联国提供保障的方向读取当前关系，`subjects` 提供候选国及其当前宗主 `overlord`。两者描述预览候选的当前关系。正常查询使用已有跨日采样窗口，按候选国家共享采集宗属绑定。

## 宣战理由与议和规则

D06的 `allowed_terms` 按攻守双方提供CB声明的正当条款 `declared_justified`，以及配置中的省份、国家、必需条约和吞并条件。ROOT、FROM保留游戏配置的作用域含义，条件由具体方案的原生预览求值。`forbidden_terms` 提供CB已明确禁用的条款类别。完整视图保留原生声明、待求值定义及覆盖情况。

`beneficiaries` 提供所查CB的 `war_goal_candidates` 和当前已选的 `selected_war_goal`，每项包含国家及目标省份。原生默认受益对象按既有合同解析为宣战国，无省份战争目标的 `province_id` 为null。

`cost_rules` 按所选CB提供攻守双方声明的战争分数、侵略扩张及威望倍率。`applies_to` 列出适用的条款标识，`province_conditions` 保留配置中的省份条件及ROOT、FROM作用域符号。存在其它条款专用倍率时，使用 `other_terms_warscore_multiplier` 单独提供。这些规则支持宣战前比较收益和代价，具体和约按所选条款、对象及条件计算。

例如，夺回核心CB的进攻方规则可返回以下内容。

```json
{
  "warscore_multiplier": 0.75,
  "aggressive_expansion_multiplier": 0.25,
  "prestige_multiplier": 1,
  "applies_to": ["po_demand_provinces", "po_return_cores"],
  "province_conditions": [{"is_core": "ROOT"}]
}
```

## 当前战争议和候选

P01按当前战争及指定行动读取候选和方案。查询割让省份时，传入 `action_id="cede_province"`，并在 `peace_context` 中提供当前战争编号和方向。空 `terms` 请求候选发现，传入具体条款则预览该方案。默认白和平查询通常没有省份候选表。

```json
{
  "topic": "P01",
  "object": {"type": "war", "war_id": "war_b39bfc70a19596eb_00000001", "actor": "FRA", "recipient": "BUR"},
  "fields": ["terms", "candidates", "beneficiaries"],
  "parameters": {
    "action_id": "cede_province",
    "peace_context": {"war_id": "war_b39bfc70a19596eb_00000001", "direction": "demand", "terms": []}
  }
}
```

`candidates` 每行提供行动、省份、受益国、名称和选择状态。`selectable` 为true或false时表示已有原生逐项检查，null表示该候选尚未取得逐项检查结果。`beneficiaries.candidates` 按受益国汇总候选省份及已检查可选、已检查不可选、未检查的省份。

`terms` 提供原生实际应用的条款，`selected_plan` 提供实际方案的受益国家、合法性及可读原因。请求条款未被应用时，`terms` 与 `selected_plan` 为null，`requested_plan` 保留请求受益国家、`applied=false`及选择原因。例如以下为ORL取得省88的失配结果节选。

```json
{
  "terms": null,
  "beneficiaries": {
    "selected_plan": null,
    "requested_plan": {
      "countries": ["ORL"],
      "applied": false,
      "selection_reason": "请求的省份和受益国组合不在当前原生候选中。"
    }
  }
}
```

## 入站提议状态

C03的pending_matters提供requests及proposals。requests保留请求编号、行动、双方、阶段、业务状态及复核类别，status=unknown表示执行结果仍需复核。proposals为null表示当前原生提议集合未知，空列表表示已读取的集合为空。还有后续请求页时返回next_after_request_id，下一次查询将它作为parameters.after_request_id传入。

A04通过proposal_id查询提议。proposal_status为observed_pending时表示曾观察到进入待回应队列，当前是否仍可回应可联合查询currently_pending，并使用parameters.fresh_pending=true即时检查。成功取得的检查结果在查询期间游戏时间正常推进时继续交付，状态对应本次实际观测。

C04订阅diplomatic_request_result时，event_id、event_type、event_objects、event_date和event_payload均取自对应执行结果的事件快照，可直接交付所选字段。请求编号可作为筛选条件。

C04按`request_id`直接查询时返回同一执行结果事件快照。`event_payload.request`保留请求编号、行动、执行状态、游戏结果及业务结果。任务派遣或停止的`result`提供`task_before`、`task_after`和已取得的实际`date`，内部原生状态和证据散列保存在完整视图中。

捕获原生待回应队列的删除后，proposal_status为inactive，currently_pending为false。捕获明确的到期分支时，状态为expired。当前查询和diplomatic_proposal订阅均使用同一个提议编号关联这些状态，已确认的到期原因优先保留。inactive只说明这份提议已结束，具体的接受、拒绝或撤回原因需要对应业务事件提供。

```json
{
  "proposal_id": "5eaed014883cfbf465ecbb2e9a31de9d",
  "proposal_status": "inactive",
  "currently_pending": false
}
```

提议结束后的查询保留原有行动及已知条款，尚未取得的可变条款继续为null。结束日期和采集来源保存在完整视图中。

## 关系变化

C04的relation_changed事件通过event_payload提供actor、recipient、relation_kind及before、after状态。保证独立的变化包含active和双方各自提供保证的布尔值。原生采集路径、命令状态、命令模式、采集日期及内部序号保存在完整视图中。

R01的country_pair查询中，actor和recipient始终标识所选国家对。所选recipient关系角色字段在简洁输出中使用relation_recipient，以便同时表示查询目标和关系受益方。完整视图沿用原字段名，各角色的未知值继续为null。

R01的country查询按`relations`逐条返回关系。每条包含`partner`和`relation_type`，以及所选的状态、日期等字段。定向关系保留`direction`及已知的`grantor`、`recipient`，同一国家的双向关系分别列出。结盟、王室联姻等对称关系省略不适用的授予方和接受方。

N05的`diplomat_tasks`返回已观察的外交官数量、可用数量及`instances`任务列表。每行提供`state`及已知的任务、行动国和目标国，空闲外交官只需`{"state":"idle"}`。内部引用、动作编码和解析状态保存在完整视图中。

W02的`war_score`提供当前战争分数`total`、上限`max_score`、统计方式`mode`和观察方向`perspective`。`goal`提供战争目标累计分数及其上限。原生校验标志、缩放前数值和提示文本保存在完整视图中。

C04的rival_changed通知提供actor、recipient、operation及before、after状态。状态包含宿敌数量count、所选国家是否为宿敌target_active，以及可读的起始日期target_since。替换宿敌时还提供old_rival及其old_active、old_since，无对应日期时返回null。完整视图保留原始日期和记录计数依据。

国家对的guarantee表示actor向recipient提供的保证独立，military_access表示actor从recipient获得的军事通行。关系生效时，grantor提供对应权利，relation_recipient获得对应权利，因此保证独立的grantor为actor，军事通行的grantor为查询目标recipient。关系未生效时，角色不适用，简洁输出为null。

这两类关系通过现有方向性缓存批量读取，同次查询共用一次采集。读取失败时复用原有行动检查保留可用状态值，角色按实际取得情况返回。国家关系网视图继续使用received与granted区分双向关系。

R03的truce_until按actor到recipient方向读取直接停战，默认采用已取得的游戏日期字符串，如1475.11.1。未设置该方向停战时返回null，完整记录保留原生时钟值。


## 战争态势

W01的 `leaders` 提供当前双方阵营的战争领袖，`our_side` 对应观察国所在阵营，`opposing_side` 对应对方阵营。它复用同次原生参战名单的向量顺序和已确认的当前领袖语义。例如法国所在阵营由萨伏依领导时，可返回 `{"our_side": "SAV", "opposing_side": "BUR"}`。仅查询战争编号或领袖时，按所选字段返回结果。

W01在游戏时间正常前进时保留本次采样取得的战争信息，完整结果记录采样时间范围。

W03使用country对象查询occupations、blockades和current_forces。前两项共用一次所选国家领土采集，沿其拥有省份列表读取。occupations提供owned_provinces、observed_provinces、occupied_provinces及按控制国汇总的occupiers。blockades提供owned_provinces、observed_provinces和blockaded_provinces。受占领和受封锁数量均在各自observed_provinces范围内统计。

country视图的current_forces复用N02、F02的现有军力来源。本国输出army_regiments和navy_ships，外国输出army_soldiers和navy_ships。字段名直接说明团数、士兵人数及舰船数，未知组件返回null。查询当前规模时，完整视图也只保留该组件的业务值与状态。

```json
{
  "topic": "W03",
  "object": {"type": "country", "country": "ENG"},
  "fields": ["occupations", "blockades", "current_forces"]
}
```

`war` 视图的 `actor` 填当前会话配置的观察国，`recipient` 填对手。两国同时参与多场战争时，用 `war_id` 选定其中一场。W01 在 `war_candidates` 中给出可直接用作下一次查询 `object` 的对象，每项包含 `type`、`war_id`、`actor` 和 `recipient`。默认输出包含本次选定的 `war_id`。`occupations`、`blockades` 和 `current_forces` 根据 W01 的参战名单，按 `our_side` 和 `opposing_side` 列出双方国家的数据。

war_id在当前采集会话中标识具体战争对象。战争移出游戏的当前活跃战争名单、对象析构或同一地址创建新战争对象时，原编号退休。新对象取得新编号。退休编号的实时查询返回无可用值，重新查询W01可取得当前编号。已保存战报保留原编号，用于该会话的历史筛选。

`current_forces` 在战争视图中提供各参战国的当前全国军力，`army_soldiers` 为士兵数，`navy_ships` 为舰船数。查询逐国检查外国军力的可见条件。`country` 视图查询法国观察国自身时沿用 N02 的 `army_regiments`，其他观察国的本国查询使用 `army_soldiers`。各字段每批共用最多 8 国的身份核对结果。

```json
{
  "topic": "W03",
  "object": {"type": "war", "actor": "FRA", "recipient": "ENG"},
  "fields": ["occupations", "blockades", "current_forces"]
}
```

battle_losses沿用逐场战报历史来源，提供战役引用及每场损失。服务通过既有battle-stream配置接入战报记录，战争筛选使用只含war_id的war对象，其分页条件遵循战报接口。

reinforcement_change默认以force_change输出，提供from_date、to_date和net_change。它将当前军力与同一观察方、游戏会话及国家或战争的最近一次军力观测相减，正值表示规模增加，负值表示规模减少。两次日期可以不同，差值同时包含损失、新建、解散、补充等影响。country视图沿用团数或士兵数的对应字段，war视图沿用双方各成员的士兵数和舰船数。

该字段复用现有information数据库中的查询记录。单查变化也只采集一次当前军力，并保存本次规模供下次比较。首次没有历史读数时force_change为null。新参战国及前后缺失的组件同样返回null，其余组件继续比较。历史读数和比较所用的结果编号保留在完整视图中。

```json
{
  "topic": "W03",
  "object": {"type": "war", "actor": "FRA", "recipient": "ENG"},
  "fields": ["current_forces", "reinforcement_change"]
}
```

## 和约后续影响

P06提供所选和约的长期影响。obligations查询持续义务，new_truce查询预计的新停战期限，integration_conditions查询新属国的整合要求，restart_conditions查询停战及双方地位变化造成的再战约束。先用W01取得war_id，再通过peace_context指定索取或让步方向及具体条款。服务复用一次原生和约预览确认实际选中项，并读取当前生效规则。这里描述拟议和约的后果，实际履行情况由执行后的状态查询确认。

解约时，`current_relationships` 按条约伙伴报告本次能核对的同盟与联姻。`present=false` 表示两类关系均已读到且未生效，`present=null` 表示无法确认。两个外国之间的关系目前会给出范围原因。`future_restriction` 另外报告重建条约限制及配置给出的年数。

```json
{
  "topic": "P06",
  "object": {"type": "war", "actor": "FRA", "recipient": "ENG"},
  "fields": ["new_truce", "obligations"],
  "parameters": {
    "peace_context": {
      "war_id": "war_0123456789abcdef_00000001",
      "direction": "demand",
      "terms": [{"action_id": "war_reparations", "payer": "ENG", "claimant": "FRA"}]
    }
  }
}
```

以下展示默认结果items中的一项，规则值以实际配置为准。

```json
{
  "actor": "FRA",
  "recipient": "ENG",
  "war_id": "war_0123456789abcdef_00000001",
  "new_truce": {"if_signed_on": "1470.8.17", "estimated_until": "1476.9.1"},
  "obligations": [{
    "type": "war_reparations",
    "payer": "ENG",
    "recipient": "FRA",
    "income_percent": 10,
    "duration_years": 10
  }]
}
```

战争赔款给出支付方、接收方、收入比例与年限。废约限制给出国家、相关伙伴与年限。贸易转移给出提供国、接收国和贸易竞争力比例，end_condition为truce_ends，表示持续于停战期；duration_years为null，具体日期可联合查询new_truce。强制附庸、建立联合统治和转移属国给出双方、后续类型及details中的贡赋与兵役规则，包括附庸税倍数、年度朝贡、参与宗主战争、陆军上限贡献百分比及人力和水手贡献系数。各规则值的含义沿用S03。

转移属国时，先复用S03读取该国当前类型，再按原生规则确定新关系。当前类型的created_by_overlord为true时转为client_vassal，其余为vassal。索取时接收国为actor，让步时为recipient。多个转移对象分别判断，共享有效类型配置读取。后续整合要求与义务均采用新类型的配置。

规则读取支持defines.lua中的NDiplomacy数值表和启用模组的直接数值赋值，按有效文件覆盖顺序处理。相关表达式和条件赋值当前返回null。查询期间游戏日期正常前进时，已取得的义务值继续可用。

new_truce按查询当日签约推算谈判双方的直接停战期限。if_signed_on给出计算采用的签约日期，estimated_until给出预计截止日。计算复用所选和约的整数战争分数费用、当前分数上限、配置中的停战年数及原生日期规则。与obligations联合查询共用一次所选和约预览，计算输入保留在完整视图中。

P02.war_score_cost在完整peace_context所选预览中返回整数战争分数，10表示10点。P06复用同一费用来源，按原生结算规则将费用限制在0至当前分数上限，再计算期限。

integration_conditions按新建宗属关系列出subject、overlord、subject_type与可用methods。每种方式给出method、minimum_subject_years、base_diplomatic_cost_per_development、progress_liberty_desire_below和scripted_conditions。当前基础配置的附庸等待10年，联合统治等待50年，每发展度基础成本8点外交点，整合进度要求自由欲低于50。联合统治另给出same_religion_group_required及overlord_provinces_at_least_subject。实际值随生效配置变化。

scripted_conditions保留游戏配置中的条件关系，每项when成立时要求满足requires。overlord和subject明确对应宗主与属国，列表保留条件顺序及OR、NOT等组合。例如当前配置要求属国对宗主好感至少190，另有政府属性和国家修正相关条件。未来开始整合时，仍按当时的国家状态和行动预览判断可用性及有效总成本。

restart_conditions给出if_signed_on与without_truce_break_after，表示按所示日期签约后，直接停战约束解除的预计日期。方案新增双方宗属关系时，还给出actor_becomes_subject或recipient_becomes_subject，以及该类型的independence_war_allowed_by_type或overlord_attack_allowed_by_type。全吞并谈判一方时，countries_removed列出消失的国家标签。其它宣战条件可通过宣战预览查询。

白和平等没有新增持续义务或宗属关系的已选方案，相应列表为空，同时仍可计算停战日期和再战约束。游戏没有实际选中请求条款时，请求字段返回null。

## 公开领土兴趣

G05围绕土地承诺、联盟摩擦和议和分配，查询所选候选省份的公开兴趣。country_pair的双方包含逻辑观察国FRA，parameters.province_ids传入1至32个不重复省份编号。单省查询使用province对象，并在parameters.country指定比较国家。

interests按国家分别列出vital重要利益与strategic战略利益省份，分类对应游戏公开利益地图提示。conflicts列出双方均有兴趣的候选省份，可据此讨论分配和承诺。visibility列出visible已发现省份和hidden未发现省份，已发现省份的兴趣计算缺少必要对象时另列unavailable。兴趣与交集在已发现且可计算的候选范围内汇总。当前交付范围为调用者选定的候选省份。

country字段提供国家对。默认简洁输出已包含actor、recipient时合并这项重复信息。完整视图保留全部所选字段。读取复用现有原生帧线程查询通道，按候选集合批量执行公开地图的兴趣谓词。

```json
{
  "topic": "G05",
  "object": {"type": "country_pair", "actor": "FRA", "recipient": "CAS"},
  "fields": ["interests", "conflicts", "visibility"],
  "parameters": {"province_ids": [167, 168, 173]}
}
```

## 数值范围和结构化业务值

有范围的值使用current、max及需要时的min。稳定度为−3至3，厌战度为0至20，腐败度为0至100，威望为−100至100。这里使用常规游戏范围，保留实际读取值。

N02的army_regiments与navy_ships分别表示军团数和舰船数，max来自所查force_limits。仅请求数量而未取得上限时max为null。manpower与sailors同样返回current/max；选择manpower和max_manpower可同时读取后备人力与最大人力，两者均以人数表示，组合查询可省略reference_recipient。选择sailors和max_sailors可同时读取当前及最大水手数，组合查询可省略reference_recipient。

N03的morale包含已换算的army与navy士气，discipline_percent表示纪律百分数。N04使用overextension_percent及religious_unity_percent表示百分数，100表示100%；实际值可以超过100。average_unrest来自国家平均叛乱度缓存，表达其原有含义。

F04的war_exhaustion表示所选外国的厌战度，同样使用current、min和max。通过country选择目标国家，FRA为当前支持的逻辑观察国，查询无需额外参数。它用于判断对手或盟友的战争承受能力。

F04选择unrest时，默认输出average_unrest，与N04沿用同一个国家平均叛乱度缓存。单位为点，保留负值。该字段沿目标国家绑定与country-view准入读取，可与厌战及受占领摘要共用一次采集。

F04的succession_risk提供当前公开继承指标，包含ruler_age、heir_present、heir_age、heir_claim和senior_country。年龄以年表示，继承权强度使用current/max和游戏分类weak、average、strong。senior_country沿用人物来源中的上级统治者国家。原生NO_HEIR分支对应heir_present=false，继承人栏不适用时相关值为null。现有S04来源提供这些组件，完整人物名称和界面文本通过S04按需查询。

```json
{
  "country": "ENG",
  "succession_risk": {
    "ruler_age": 20,
    "heir_present": true,
    "heir_age": 5,
    "heir_claim": {"current": 89.642, "max": 100, "category": "strong"},
    "senior_country": null
  }
}
```

F04的occupied汇总所选国家领土的受占领情况。owned_provinces为该国拥有的省份总数，observed_provinces为法国观察方已发现且控制国可确定的省份数，occupied_provinces为其中由其它国家或叛军控制的数量，occupiers按控制国标签汇总。所有占领数量均在observed_provinces范围内统计，REB表示叛军。两项省份总数相等时摘要覆盖全部领土。查询沿该国的拥有省份列表读取，单查occupied会跳过厌战度数值读取，与war_exhaustion组合时共用一次采集。

```json
{
  "country": "ENG",
  "occupied": {
    "owned_provinces": 40,
    "observed_provinces": 40,
    "occupied_provinces": 38,
    "occupiers": {"FRA": 38}
  }
}
```

R06的ai_attitude表示actor对recipient的当前AI态度，使用country_pair对象，双方中包含逻辑观察国FRA。值沿用原生态度名称并省略attitude_前缀，例如friendly、hostile、rivalry和neutral。两个方向分别查询，结果保留actor和recipient；好感使用R04，具体外交行动接受度使用对应行动预览。

R06的history表示actor对recipient的历史关系，包含historical_friend和historical_rival两个布尔值。可与ai_attitude一起查询，共享一次国家绑定与采集。单独选择history时只读取历史关系列表。字段无可用值时返回null，已确认缺席时返回false。

R06的personality表示actor当前生效的AI战略性格，如balanced、diplomat、militarist、capitalist和colonialist，共享君主时按游戏规则取实际生效来源。它与对具体国家的ai_attitude分别返回。relationship_tendency复用ai_attitude的原生态度值；单独选择时使用该字段名，同时选择两者时简洁输出保留ai_attitude，完整视图保留两个所选字段。R06字段可在同一次采集中组合读取。

S03的liberty_desire表示属国当前有效自由欲，范围0到100，由游戏原生查询计算。loyalty沿用属国对宗主的当前AI态度，如loyal、disloyal或rebellious。使用country对象选择属国，也可用包含FRA的country_pair选择双方之间的属国关系。FRA为当前支持的逻辑观察国，外国属国可直接用country查询。独立国家或没有对应宗属关系时字段不适用，简洁输出中数值为null。只选loyalty时读取现有态度缓存。

F04的subject_loyalty复用上述来源，包含overlord、liberty_desire和loyalty，便于判断外国属国压力。有效自由欲计算在已有原生只读查询线程执行，允许刷新游戏内部计算缓存。

S03的support_independence返回所选属国当前独立支持关系中的其它国家标签列表，空列表表示没有相关关系。它可单独查询，也可与自由欲、忠诚态度组合读取；单独查询时只读现有关系缓存。

S03的tribute和levy提供当前已加载属国类型的贡赋与兵役规则，用于比较不同依附关系的收益和负担。游戏已处理类型继承，字段读取其生效定义。tribute中的vassal_tax_multiplier以普通附庸税额为基准，1表示普通附庸基准额，0表示该类型免除此项；annual_tribute表示该类型采用年度朝贡机制。levy中的land_force_limit_share_percent表示属国陆军上限向宗主贡献的基础百分比，manpower_factor和sailors_factor分别表示类型定义中的人力、水手贡献系数。这些规则在实际结算时还会结合当前关系状态、国家修正及游戏计算。实际每月支付金额与最终增加的上限或人数属于其它业务值。

两个字段可单独或组合查询，读取现有类型定义。默认输出仅包含所选规则值，完整视图同时记录subject_type。独立国家返回null。普通附庸的规则示例如下。

```json
{
  "tribute": {"vassal_tax_multiplier": 1, "annual_tribute": false},
  "levy": {"land_force_limit_share_percent": 10, "manpower_factor": 0, "sailors_factor": 0}
}
```

S03的integration提供overlord、type_rules、can_start、total_diplomatic_power、in_progress和diplomatic_power_spent。overlord明确该属国的宗主，开始条件和成本均对应宗主整合该属国。type_rules中的annexation_allowed与union_integration_allowed分别表示该类型允许外交吞并或联合统治整合，same_religion_group_required表示整合要求同宗教组，base_diplomatic_cost_per_development表示每发展度的基础外交点成本。can_start使用宗主对该属国的当前原生动作检查，包含动作可见性、通用条件、具体开始条件及外交官可用性；total_diplomatic_power由游戏计算当前有效总成本，包含适用修正。当前无法开始且取得条件文本时，conditions保留原生说明。

in_progress表示宗主与属国之间存在当前整合任务，diplomatic_power_spent表示该任务已投入的外交点。双方均没有对应任务时返回false和0。任务存在但进度无法读取时保留已知规则，相关值返回null。类型禁止外交整合时can_start为false，总成本不适用并返回null。独立国家的integration整体返回null。只查类型贡赋、兵役或独立支持时继续只读缓存；整合与自由欲组合查询共用一次原生预览。完整视图保留条件文本的读取和截断状态。

战略战报选择B01的end_date、location、sides、winner及B02的losses，提供日期、地点、参战双方与观察国所在侧、胜负和双方损失。end_date在简洁输出中使用1470.1.14形式。B01胜方只保留countries和observer_outcome。

`B01` 按 `event_id` 读取已采集的单场战斗。按战争找战报时，先查 `W03.battle_losses` 或 `H01.battle_sequence`，再从 `event_refs` 取 `event_id`。

B04的details选择现有战报组合中的可读文本。其它战报字段按需选择，B02的initial_forces和remaining_forces分别提供初始兵力和剩余兵力。

B04.details默认包含双方国家、观察国所在侧以及同场已取得的结果文字，沿用完整视图中result_text的组合。部分文字缺失时，默认输出继续保留已知内容。完整视图的details.value.result_text.complete与selected_text_complete表示所选文字和已声明的双方身份是否全部取得，并包含输出长度限制的影响。原生窗口副本及显示状态沿各自来源字段记录。

B01.war_id采用采集进程共享注册表中的战争编号，可用于同一采集会话的战争历史筛选。已确认一方仅有REB叛军、另一方为国家部队且原生战争上下文为空时，该字段不适用，默认返回null。完整视图使用not_applicable说明这种情况。按战争筛选的战报历史会跳过这些战斗，国家级战报历史继续包含它们。


任务M01–M04默认返回tasks，包含任务标识、名称、完成及可完成状态、前置条件、已观测的具体条件和目标。宣称奖励保留目标及条件，granted为null表示尚无已授予的事实。所选其它奖励字段继续保留。

范围示例为`"stability": {"current": 1, "min": -3, "max": 3}`，军力示例为`"army_regiments": {"current": 56, "max": 56}`。这些格式应用于默认简洁视图，查询选择器仍使用原字段名stability、army_size等。

## 外交等待期限

A01的diplomat_required表示所选行动是否需要外交官，复用行动预览中的原生需求。cooldown表示该行动当前是否因最近派遣过外交官而受到等待期限阻挡。blocked=true时，available_on返回游戏界面给出的可再次派遣日期，保留其可读日期格式。blocked=false表示当前通用动作条件已通过。其它条件仍会影响行动是否合法。

执行回执在确认是同一项外交官冷却时，也在 `result.reason.cooldown` 返回 `blocked` 和 `available_on`。改善关系动作收到原生通用复检拒绝时，服务可在同一游戏日只读复查一次。

`R05` 查询信任与人情余额可省略 `kind`。`trust` 表示 `recipient` 对 `actor` 的信任。`favors_available` 表示 `actor` 可向 `recipient` 使用的人情。需要同时查看积累任务时，可用独立的 `R05.favor_tasks` 查询。

```json
{
  "actor": "FRA",
  "recipient": "GEL",
  "action_id": "ask_military_access",
  "diplomat_required": true,
  "cooldown": {"blocked": true, "available_on": "1470年11月27日"}
}
```

该字段复用本次原生行动预览，识别中文、英文的ENROUTE等待提示。其它语言或当前提示未提供等待原因且通用条件未通过时，cooldown返回null。单独请求cooldown仍只执行一次已有行动预览。完整视图记录该字段来自等待提示或通用条件通过。
