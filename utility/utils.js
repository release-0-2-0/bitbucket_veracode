var parseString = require('xml2js').parseString;
const fs = require('fs');
const path = require('path');

function processStaticResultsXML(xml){
    const severityArray = ['Informational','Very Low','Low','Medium','High','Very High']

    let policy_results = {
        scan_types: ["Static Analysis"],
        num_findings: 0,
        num_very_high: 0,
        num_high: 0,
        num_medium: 0,
        num_low: 0,
        num_very_low: 0,
        num_informational: 0,
        findings: []
    }
    let all_results = {
        scan_types: ["Static Analysis"],
        num_findings: 0,
        num_very_high: 0,
        num_high: 0,
        num_medium: 0,
        num_low: 0,
        num_very_low: 0,
        num_informational: 0,
        findings: []
    }

    parseString(xml, function (_err, result) {
        // Convert XML to well defined Object
        let output = JSON.stringify(result, null, 2)
        output = output.replace("static-analysis", "static_analysis");
        output = output.replace("flaw-status", "flaw_status");
        output = output.replace("xmlns:xsi", "xmlns_xsi");
        output = output.replace("xsi:schemaLocation", "xsi_schemaLocation");
        output = output.replace("sev-1-change", "sev_1_change");
        output = output.replace("sev-2-change", "sev_2_change");
        output = output.replace("sev-3-change", "sev_3_change");
        output = output.replace("sev-4-change", "sev_4_change");
        output = output.replace("sev-5-change", "sev_5_change");
        const res = JSON.parse(output);
        // console.log('res in results file', res)
        // Iterate through the Sevrities
        for (let i=0; i<res.detailedreport.severity.length; i++) {
            let severity = parseInt(res.detailedreport.severity[i].$.level); 
            let theCategory = res.detailedreport.severity[i].category;
            if (theCategory) {
                for (let j=0; j< theCategory.length; j++) {
                    for (let k=0; k<theCategory[j].cwe.length; k++) {
                        for (let l=0; l<theCategory[j].cwe[k].staticflaws.length; l++) {
                            for (let m=0; m<theCategory[j].cwe[k].staticflaws[l].flaw.length; m++) {
                                let static_finding = {
                                    issue_id: parseInt(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.issueid),
                                    severity: parseInt(res.detailedreport.severity[i].$.level),
                                    severity_text: severityArray[parseInt(res.detailedreport.severity[i].$.level)],
                                    category: theCategory[j].$.categoryname,
                                    cwe_id: theCategory[j].cwe[k].$.cweid,
                                    issue_type: theCategory[j].cwe[k].$.cwename,
                                    source_file: theCategory[j].cwe[k].staticflaws[l].flaw[m].$.sourcefilepath+theCategory[j].cwe[k].staticflaws[l].flaw[m].$.sourcefile,
                                    line: parseInt(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.line),
                                    function_prototype: theCategory[j].cwe[k].staticflaws[l].flaw[m].$.functionprototype,
                                    description: extractDescriptionXML(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.description),
                                    remediation: extractRemediationXML(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.description),
                                    additional_remediation: ""
                                }
                                let finding = {
                                    type: "Static Analysis",
                                    static: static_finding
                    
                                }
                                // Add to All Findings
                                all_results.findings.push(finding);
                                switch (static_finding.severity) {
                                    case 0: { 
                                        all_results.num_informational++;
                                        break; 
                                    } 
                                    case 1: { 
                                        all_results.num_very_low++;
                                        break; 
                                    } 
                                    case 2: { 
                                        all_results.num_low++;
                                        break; 
                                    } 
                                    case 3: { 
                                        all_results.num_medium++;
                                        break; 
                                    } 
                                    case 4: { 
                                        all_results.num_high++;
                                        break; 
                                    } 
                                    case 5: { 
                                        all_results.num_very_high++;
                                        break; 
                                    } 
                                }
                                all_results.num_findings++;
                                // Add to Policy Findings
                                if (theCategory[j].cwe[k].staticflaws[l].flaw[m].$.affects_policy_compliance === "true") {
                                    policy_results.findings.push(finding);
                                    switch (static_finding.severity) {
                                        case 0: { 
                                            policy_results.num_informational++;
                                            break; 
                                        } 
                                        case 1: { 
                                            policy_results.num_very_low++;
                                            break; 
                                        } 
                                        case 2: { 
                                            policy_results.num_low++;
                                            break; 
                                        } 
                                        case 3: { 
                                            policy_results.num_medium++;
                                            break; 
                                        } 
                                        case 4: { 
                                            policy_results.num_high++;
                                            break; 
                                        } 
                                        case 5: { 
                                            policy_results.num_very_high++;
                                            break; 
                                        } 
                                    }
                                    policy_results.num_findings++;
                                }
                            }
                        }
                    }

                }
            }
        }
    
        //fs.writeFileSync('./detailedreport.json', output);
    });

    let report = {
        policy_results: policy_results,
        all_results: all_results
    }

    return report;
}

function extractDescriptionXML(details)  {
    let parts = details.split("\r\n\r\n");
    if (parts.length < 2) {
      return details;
    } else {
      return parts[0].replace("\r\n\r\n", "\r\n")
    }
}

function extractRemediationXML(details){
    let parts = details.split("\r\n\r\n");
    if (parts.length == 1) {
      return details;
    } else if (parts.length == 2) {
      return parts[1].replace("\r\n\r\n", "\r\n")
    } else {
        return (parts[1] + " \r\n" + parts[2]).replace("\r\n\r\n", "\r\n");
    }
}

async function attacheResult(veracodeArtifactsDir, fileName, result) {
    try {
        const filePath = path.join(veracodeArtifactsDir, fileName);
        fs.writeFileSync(filePath, result);
    } catch (error) {
        console.error(`Error while writing ${fileName}`);
        console.log(error);
    }
}

module.exports = {
    processStaticResultsXML,
    attacheResult
}