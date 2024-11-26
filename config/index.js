function veraocdeConfig() {
    return {
      applicationUri: '/appsec/v1/applications',
      hostName: 'api.veracode.com',
      policyUri: '/appsec/v1/policies',
      teamsUri: '/api/authn/v2/teams',
      pollingInterval: 30000,
      moduleSelectionTimeout: 60000,
      scanStatusApiTimeout: 600000, // 10 minutes
      defaultPolicyUuid: '9ab6dc63-29cf-4457-a1d1-e2125277df0e',
      sandboxScanName: 'Gitlab extension scans - ',
      sandboxUri: '/appsec/v1/applications/${appGuid}/sandboxes',
    }
}

function appConfig() {
    return {
      logPrefix: `[veracode]: `,
      policyScanResult: "policy_scan_results.json",
      pipelineScanFile: "pipeline.json",
      filteredScanFile: "filtered_results.json",
      scaScanFileName: "sca_results.json"
    };
  }

module.exports = {
    veraocdeConfig,
    appConfig
}