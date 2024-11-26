const axios = require("axios");
const crypto = require('crypto');
const sjcl = require('sjcl');
const { veraocdeConfig, appConfig } = require('../../config');
const authorizationScheme = "VERACODE-HMAC-SHA-256";
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

async function getVeracodeApplication(vid, vkey, applicationName, policyName, teams, createprofile) {
    const responseData = await getApplicationByName(vid, vkey, applicationName);
    const profile = isProfileExists(responseData, applicationName);
    if (profile.exists) {
        return profile.veracodeApp;
    } else {
        if (createprofile) {
            const veracodePolicy = await getVeracodePolicyByName(vid, vkey, policyName);
            const resource = {
                resourceUri: veraocdeConfig().applicationUri,
                resourceData: {
                    profile: {
                        business_criticality: "HIGH",
                        name: applicationName,
                        policies: [
                            {
                                guid: veracodePolicy.policyGuid
                            }
                        ],
                        teams: []
                    }
                }
            };
            const response = await createResource(vid, vkey, resource);
            const appProfile = response.app_profile_url;
            return {
                'appId': response.id,
                'appGuid': response.guid,
                'oid': appProfile.split(':')[1]
            };
        }
        return { 'appId': -1, 'appGuid': -1, 'oid': -1 };
    }
}

async function getApplicationByName(vid, vkey, applicationName) {
    const resource = {
        resourceUri: veraocdeConfig().applicationUri,
        queryAttribute1: 'name',
        queryValue1: encodeURIComponent(applicationName)
    };
    const response = await getResourceByAttribute(vid, vkey, resource);
    console.log(`${appConfig().logPrefix} Response from create profile on veracode platform for applicationName ${applicationName} : ${JSON.stringify(response)}`);
    return response;
}

async function getSandboxesByApplicationGuid(appGuid, appId, appKey) {
    const resource = {
        resourceUri: veraocdeConfig().sandboxUri.replace('${appGuid}', appGuid),
        queryAttribute1: '',
        queryValue1: ''
    };
    const response = await getResourceByAttribute(appId, appKey, resource);
    console.log(`${appConfig().logPrefix} Response from retriving sandboxes by application guuid ${appGuid} : ${JSON.stringify(response)}`);
    return response;
}

async function deleteResourceById(vid, vkey, resource) {
    const resourceUri = resource.resourceUri;
    const resourceId = resource.queryValue1;

    const queryUrl = `${resourceUri}/${resourceId}`;
    const headers = {
        Authorization: calculateAuthorizationHeaderV2({
            id: vid,
            key: vkey,
            host: veraocdeConfig().hostName,
            url: queryUrl,
            method: 'DELETE',
        }),
    };
    const appUrl = `https://${veraocdeConfig().hostName}${resourceUri}/${resourceId}`;
    try {
        return await axios.delete(appUrl, { headers });
    } catch (error) {
        console.log('Error while executing delete resource request :');
        console.log(error);
    }
}

function calculateAuthorizationHeaderV2(params) {
    const uriString = params.url;
    const data = `id=${params.id}&host=${params.host}&url=${uriString}&method=${params.method}`;
    const dateStamp = Date.now().toString();
    const nonceBytes = newNonce();
    const dataSignature = calulateDataSignature(params.key, nonceBytes, dateStamp, data);
    const authorizationParam = `id=${params.id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    const header = authorizationScheme + ' ' + authorizationParam;
    return header;
}

async function getResourceByAttribute(vid, vkey, resource) {
    const resourceUri = resource.resourceUri;
    const queryAttribute = resource.queryAttribute1;
    const queryValue = resource.queryValue1;
    const queryAttribute2 = resource.queryAttribute2;
    const queryValue2 = resource.queryValue2;
    var urlQueryParams = queryAttribute !== '' ? `?${queryAttribute}=${queryValue}` : '';
    if (queryAttribute2) {
        urlQueryParams = urlQueryParams + `&${queryAttribute2}=${queryValue2}`;
    }
    const headers = {
        'Authorization': calculateAuthorizationHeader(vid, vkey, veraocdeConfig().hostName, resourceUri, urlQueryParams, 'GET')
    };
    const appUrl = `https://${veraocdeConfig().hostName}${resourceUri}${urlQueryParams}`;
    try {
        const response = await axios.get(appUrl, { headers });
        return response.data;
    } catch (error) {
        console.log(`${appConfig().logPrefix} Error while calling api with resource : ${JSON.stringify(resource)}: ${error}`);
    }
}

function calculateAuthorizationHeader(id, key, hostName, uriString, urlQueryParams, httpMethod) {
    uriString += urlQueryParams;
    let data = `id=${id}&host=${hostName}&url=${uriString}&method=${httpMethod}`;
    let dateStamp = Date.now().toString();
    let nonceBytes = newNonce(nonceSize);
    let dataSignature = calulateDataSignature(key, nonceBytes, dateStamp, data);
    let authorizationParam = `id=${id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    let header = authorizationScheme + " " + authorizationParam;
    return header;
}

function calculateAuthorizationHeaderV2(params) {
    const uriString = params.url;
    const data = `id=${params.id}&host=${params.host}&url=${uriString}&method=${params.method}`;
    const dateStamp = Date.now().toString();
    const nonceBytes = newNonce(nonceSize);
    const dataSignature = calulateDataSignature(params.key, nonceBytes, dateStamp, data);
    const authorizationParam = `id=${params.id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    const header = authorizationScheme + ' ' + authorizationParam;
    return header;
}

function newNonce(nonceSize) {
    return crypto.randomBytes(nonceSize).toString('hex').toUpperCase();
}

function calulateDataSignature(apiKeyBytes, nonceBytes, dateStamp, data) {
    let kNonce = computeHashHex(nonceBytes, apiKeyBytes);
    let kDate = computeHashHex(dateStamp, kNonce);
    let kSig = computeHashHex(requestVersion, kDate);
    let kFinal = computeHashHex(data, kSig);
    return kFinal;
}

function computeHashHex(message, key_hex) {
    let key_bits = sjcl.codec.hex.toBits(key_hex);
    let hmac_bits = (new sjcl.misc.hmac(key_bits, sjcl.hash.sha256)).mac(message);
    let hmac = sjcl.codec.hex.fromBits(hmac_bits);
    return hmac;
}

function toHexBinary(input) {
    return sjcl.codec.hex.fromBits(sjcl.codec.utf8String.toBits(input));
}


function isProfileExists(responseData, applicationName) {
    if (responseData?.page?.total_elements === 0) {
        console.log(`No Veracode application profile found for ${applicationName}`);
        return { exists: false, veracodeApp: null };
    }
    else {
        for (let i = 0; i < responseData._embedded.applications.length; i++) {
            if (responseData._embedded.applications[i].profile.name.toLowerCase() === applicationName.toLowerCase()) {
                return {
                    exists: true,
                    veracodeApp: {
                        'appId': responseData._embedded.applications[i].id,
                        'appGuid': responseData._embedded.applications[i].guid,
                        'oid': responseData._embedded.applications[i].oid,
                    }
                };;
            }
        }
        console.log(`No Veracode application profile with exact the profile name: ${applicationName}`);
        return { exists: false, veracodeApp: null };
    }
}

async function getVeracodePolicyByName(vid, vkey, policyName) {
    if (policyName !== '') {
        const responseData = await getPolicyByName(vid, vkey, policyName);
        if (responseData.page.total_elements !== 0) {
            for (let i = 0; i < responseData._embedded.policy_versions.length; i++) {
                if (responseData?._embedded?.policy_versions[i]?.name?.toLowerCase() === policyName.toLowerCase()) {
                    return {
                        'policyGuid': responseData._embedded.policy_versions[i].guid,
                    }
                }
            }
        }
    }
    return { 'policyGuid': veraocdeConfig().defaultPolicyUuid };
}

async function getPolicyByName(vid, vkey, policyName) {
    const resource = {
        resourceUri: veraocdeConfig().policyUri,
        queryAttribute: 'name',
        queryValue: encodeURIComponent(policyName)
    };
    const response = await getResourceByAttribute(vid, vkey, resource);
    return response;
}

async function createResource(vid, vkey, resource) {
    const resourceUri = resource.resourceUri;
    const resourceData = resource.resourceData;
    const headers = {
        'Authorization': calculateAuthorizationHeader(vid, vkey, veraocdeConfig().hostName, resourceUri, '', 'POST')
    };
    const appUrl = `https://${veraocdeConfig().hostName}${resourceUri}`;
    try {
        const response = await axios.post(appUrl, resourceData, { headers });
        // console.debug(`veracode: Response from ${appUrl} : ${response.data}`);
        return response.data;
    } catch (error) {
        console.debug(`veracode: Error while requesting ${appUrl} api : ${error}`);
    }
}

module.exports = { getVeracodeApplication, getApplicationByName, getResourceByAttribute, isProfileExists, getSandboxesByApplicationGuid, deleteResourceById };