import { readFileSync, writeFileSync } from 'fs';

import json2md from 'json2md';

// const scanData = JSON.parse(readFileSync("./scandata/awe-httpd-base-20230222.json"))
const scanData = JSON.parse(readFileSync('./report.json'));

const vulns = scanData.Results[0].Vulnerabilities;

const vulnsSubset = vulns.map((vuln) =>
  (({
    PkgID,
    VulnerabilityID,
    InstalledVersion,
    FixedVersion,
    PrimaryURL,
    Severity,
    Title,
    Description,
    PublishedDate,
    LastModifiedDate,
    References,
  }) => ({
    PkgID,
    VulnerabilityID,
    InstalledVersion,
    FixedVersion,
    PrimaryURL,
    Severity,
    Title,
    Description,
    PublishedDate,
    LastModifiedDate,
    References,
  }))(vuln)
);

// console.log(vulnsSubset)

const title = scanData.ArtifactName;
// console.log(title);

const osVersion = `OS Version: ${scanData.Metadata.ImageConfig.os} / ${scanData.Metadata.OS.Family} / ${scanData.Metadata.OS.Name}`;
// console.log(osVersion);

const buildDate = scanData.Metadata.ImageConfig.created;
// console.log(buildDate);

// console.log(scanData)

// let data =

// console.log(scanData)

// writeFileSync("./scandata/awe-httpd-base-20230222-subset.json", JSON.stringify(scanData, null, 2))
