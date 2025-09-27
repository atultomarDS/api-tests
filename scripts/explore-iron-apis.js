async function exploreIronAPIs() {
  try {
    console.log('🔍 Exploring Iron.xyz APIs...\n');
    
    // The MCP server is designed to work with MCP clients, not directly
    // Let's try to fetch the OpenAPI spec directly from the API
    console.log('📋 Fetching OpenAPI specification from Iron.xyz...');
    
    // Try different common OpenAPI spec paths
    const specUrls = [
      'https://api.sandbox.iron.xyz/openapi.json',
      'https://api.sandbox.iron.xyz/swagger.json',
      'https://api.sandbox.iron.xyz/api-docs',
      'https://api.sandbox.iron.xyz/docs/openapi.json',
      'https://api.sandbox.iron.xyz/v1/openapi.json'
    ];
    
    let response;
    let openApiSpec;
    
    for (const url of specUrls) {
      try {
        console.log(`Trying: ${url}`);
        response = await fetch(url);
        if (response.ok) {
          openApiSpec = await response.json();
          console.log(`✅ Found OpenAPI spec at: ${url}`);
          break;
        }
      } catch (error) {
        console.log(`❌ Failed: ${url} - ${error.message}`);
      }
    }
    
    if (!openApiSpec) {
      throw new Error('Could not find OpenAPI specification at any common path');
    }
    
    // Extract endpoints
    const endpoints = [];
    for (const [path, pathItem] of Object.entries(openApiSpec.paths || {})) {
      for (const [method, operation] of Object.entries(pathItem)) {
        if (typeof operation === 'object' && operation.operationId) {
          endpoints.push({
            path,
            method: method.toUpperCase(),
            operationId: operation.operationId,
            summary: operation.summary,
            tags: operation.tags || []
          });
        }
      }
    }
    
    console.log(`\n📊 Found ${endpoints.length} API endpoints:`);
    endpoints.forEach(endpoint => {
      console.log(`  ${endpoint.method} ${endpoint.path} - ${endpoint.summary || endpoint.operationId}`);
    });
    
    // Group by tags
    const groupedByTags = {};
    endpoints.forEach(endpoint => {
      endpoint.tags.forEach(tag => {
        if (!groupedByTags[tag]) {
          groupedByTags[tag] = [];
        }
        groupedByTags[tag].push(endpoint);
      });
    });
    
    console.log('\n🏷️  Endpoints grouped by tags:');
    Object.entries(groupedByTags).forEach(([tag, tagEndpoints]) => {
      console.log(`\n  ${tag} (${tagEndpoints.length} endpoints):`);
      tagEndpoints.forEach(endpoint => {
        console.log(`    ${endpoint.method} ${endpoint.path} - ${endpoint.summary || endpoint.operationId}`);
      });
    });
    
    return { openApiSpec, endpoints, groupedByTags };
    
  } catch (error) {
    console.error('❌ Error exploring Iron.xyz APIs:', error);
    return null;
  }
}

exploreIronAPIs();
