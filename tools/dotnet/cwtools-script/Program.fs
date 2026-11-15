open System
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open FParsec
open CWTools.Parser
open CWTools.Parser.Types
open CWTools.Utilities.Position

Encoding.RegisterProvider(CodePagesEncodingProvider.Instance)

let maxFiles = 64
let maxTotalBytes = 4 * 1024 * 1024
let parserVersion = "0.6.0-alpha"
let schema = "eu4.cwtools.script_ast.v1"

let textNode (text: string) : JsonNode = JsonValue.Create(text) :> JsonNode
let intNode (value: int) : JsonNode = JsonValue.Create(value) :> JsonNode
let decimalNode (value: decimal) : JsonNode = JsonValue.Create(value) :> JsonNode
let boolNode (value: bool) : JsonNode = JsonValue.Create(value) :> JsonNode

let readBounded (path: string) (remaining: int) =
    use stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)
    if stream.Length > int64 remaining then
        raise (InvalidDataException("aggregate_input_limit_exceeded"))
    let initialSize = int stream.Length
    use output = new MemoryStream(initialSize)
    let buffer = Array.zeroCreate<byte> 65536
    let mutable finished = false
    while not finished do
        let room = remaining - int output.Length
        let readSize = min buffer.Length (room + 1)
        if readSize <= 0 then
            raise (InvalidDataException("aggregate_input_limit_exceeded"))
        let count = stream.Read(buffer, 0, readSize)
        if count = 0 then
            finished <- true
        elif output.Length + int64 count > int64 remaining then
            raise (InvalidDataException("aggregate_input_limit_exceeded"))
        else
            output.Write(buffer, 0, count)
    output.ToArray()

let decodeInput (bytes: byte array) =
    let utf8Strict = UTF8Encoding(false, true)
    let cp1252Strict = Encoding.GetEncoding(1252, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback)
    if bytes.Length >= 3 && bytes[0] = 0xEFuy && bytes[1] = 0xBBuy && bytes[2] = 0xBFuy then
        "utf-8-bom", utf8Strict.GetString(bytes, 3, bytes.Length - 3)
    else
        try
            "utf-8", utf8Strict.GetString(bytes)
        with :? DecoderFallbackException ->
            "windows-1252", cp1252Strict.GetString(bytes)

let positionFields (node: JsonObject) (range: range) =
    node["source_line"] <- intNode (int range.StartLine)
    node["source_column"] <- intNode (int range.StartColumn)
    node["end_line"] <- intNode (int range.EndLine)
    node["end_column"] <- intNode (int range.EndColumn)

let rec statementNode (statement: Statement) : JsonObject =
    match statement with
    | CommentStatement comment ->
        let node = JsonObject()
        node["statement_kind"] <- textNode "comment"
        node["key"] <- null
        node["operator"] <- null
        node["value_kind"] <- textNode "comment"
        node["value"] <- textNode comment.Comment
        positionFields node comment.Position
        node["children"] <- JsonArray()
        node
    | KeyValue (PosKeyValue (range, KeyValueItem (key, value, op))) ->
        valueNode (Some(string key)) (Some(operatorToString op)) range value
    | Value (range, value) ->
        valueNode None None range value

and valueNode (key: string option) (op: string option) (range: range) (value: Value) : JsonObject =
    let node = JsonObject()
    node["statement_kind"] <- textNode (if key.IsSome then "key_value" else "bare_value")
    node["key"] <- (match key with Some value -> textNode value | None -> null)
    node["operator"] <- (match op with Some value -> textNode value | None -> null)
    positionFields node range
    match value with
    | String _ ->
        node["value_kind"] <- textNode "string"
        node["value"] <- textNode (value.ToRawString())
        node["children"] <- JsonArray()
    | QString _ ->
        node["value_kind"] <- textNode "quoted_string"
        node["value"] <- textNode (value.ToRawString())
        node["children"] <- JsonArray()
    | Float number ->
        node["value_kind"] <- textNode "decimal"
        node["value"] <- decimalNode number
        node["children"] <- JsonArray()
    | Int number ->
        node["value_kind"] <- textNode "integer"
        node["value"] <- intNode number
        node["children"] <- JsonArray()
    | Bool boolean ->
        node["value_kind"] <- textNode "boolean"
        node["value"] <- boolNode boolean
        node["children"] <- JsonArray()
    | Clause statements ->
        node["value_kind"] <- textNode "block"
        node["value"] <- null
        let children = JsonArray()
        for child in statements do
            children.Add(statementNode child)
        node["children"] <- children
    node

let errorNode (code: string) (message: string) =
    let error = JsonObject()
    error["code"] <- textNode code
    error["message"] <- textNode message
    error

let fileNode (path: string) (remainingBytes: int) =
    let node = JsonObject()
    let errors = JsonArray()
    node["path"] <- textNode (try Path.GetFullPath(path) with _ -> path)
    node["bytes"] <- intNode 0
    node["sha256"] <- null
    node["encoding"] <- null
    node["parse_ok"] <- boolNode false
    node["items"] <- JsonArray()
    node["errors"] <- errors
    try
        let absolutePath = Path.GetFullPath(path)
        let bytes = readBounded absolutePath remainingBytes
        node["bytes"] <- intNode bytes.Length
        node["sha256"] <- textNode (Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant())
        let encodingName, input = decodeInput bytes
        node["encoding"] <- textNode encodingName
        match CKParser.parseString input absolutePath with
        | Success (statements, _, _) ->
            let items = JsonArray()
            for statement in statements do
                items.Add(statementNode statement)
            node["parse_ok"] <- boolNode true
            node["items"] <- items
        | Failure (message, _, _) ->
            errors.Add(errorNode "cwtools_parse_error" message)
    with ex ->
        errors.Add(errorNode "input_or_decode_error" (ex.GetType().Name + ": " + ex.Message))
    node

let runPaths (paths: string array) =
    if paths.Length < 1 || paths.Length > maxFiles then
        Console.Error.WriteLine("expected_between_1_and_64_explicit_script_paths")
        2
    else
        let output = JsonObject()
        output["schema"] <- textNode schema
        let parser = JsonObject()
        parser["name"] <- textNode "CWTools"
        parser["version"] <- textNode parserVersion
        parser["entry_point"] <- textNode "CWTools.Parser.CKParser.parseString"
        output["parser"] <- parser
        output["input_limit_bytes"] <- intNode maxTotalBytes
        let files = JsonArray()
        let mutable totalBytes = 0
        for path in paths do
            let item = fileNode path (maxTotalBytes - totalBytes)
            totalBytes <- totalBytes + (item["bytes"].GetValue<int>())
            files.Add(item)
        output["total_bytes"] <- intNode totalBytes
        output["files"] <- files
        let options = JsonSerializerOptions(WriteIndented = true)
        Console.Out.WriteLine(output.ToJsonString(options))
        0

[<EntryPoint>]
let main (paths: string array) =
    runPaths paths
