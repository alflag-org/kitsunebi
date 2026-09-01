fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&kitsunebi_api::openapi_document())
            .expect("OpenAPI document must serialize")
    );
}
