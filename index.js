const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');

const repoToken = core.getInput('repo-token');
const org_name = core.getInput('org-name');
const repos = core.getInput('repo-names');
const trans_depth = parseInt(core.getInput('depth'));

const repoNames = repos.split(',');

const artifact = require('@actions/artifact');
const artifactClient = artifact.create();
const artifactName = `dependency-lists`;
let files = [];
let fileLines = [];
let pagination = null;
let checkedRepos = [];
let indent = [];
let firstIndent = false;
let depth = 0;
let vulnFileLines = [];
let vulnFileLinesSummary = [];
let vulnSummaryLines = [];
let vulnCheckedRepos = [];
const rootDirectory = '.'; // Also possible to use __dirname
const options = {
	continueOnError: false
};


let { graphql } = require('@octokit/graphql')
graphql = graphql.defaults({
	headers: {
		authorization: `token ${repoToken}`,
		Accept: 'application/vnd.github.hawkgirl-preview+json'
	}
});

// Delete this comment

// Add async function to get vulnerabilityAlerts
const getVulnerabilityAlerts = async (org, repo) => {
	const query =
		`query ($org: String! $repo: String! $cursor: String){
			repository(owner: $org, name: $repo) {
				vulnerabilityAlerts(first: 100 after: $cursor) {
					pageInfo {
						hasNextPage
						endCursor
					}
			
					nodes {
						id
						createdAt
						dismissedAt
						securityVulnerability {
							package {
								name
							}
							severity
							advisory {
								summary
								description
								references {
									url
								}
							}
						}
					}
				}
			}
		}`

	let hasNextPage = false;
	do {
		console.log(`${indent.join('')}${org}/${repo}: Finding vulnerabilities...`);

		if (vulnCheckedRepos.find(check => check.org == org && check.name == repo) != undefined) { // We've already checked this repo
			console.log(`${indent.join('')}${org}/${repo}: Already checked.`)
			return;
		}

		let getVulnResult = null;

		try {
			getVulnResult = await graphql({ query, org: org, repo: repo, cursor: pagination });
		}
		catch (e) {
			console.log(`${indent.join('')}${org}/${repo}: GraphQL query failed: ${e.message}`);
			return;
		}

		vulnCheckedRepos.push({
			"org": org,
			"name": repo
		});

		hasNextPage = getVulnResult.repository.vulnerabilityAlerts.pageInfo.hasNextPage;
		const repoVulnerabilities = getVulnResult.repository.vulnerabilityAlerts.nodes;

		for (const repoVulnerability of repoVulnerabilities) {
			console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.securityVulnerability.package.name} vulnerability found with severity ${repoVulnerability.securityVulnerability.severity}.`)
			//console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.securityVulnerability.advisory.summary}`)
			//console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.securityVulnerability.advisory.description}`)
			//console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.securityVulnerability.advisory.references.url}`)
			//console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.securityVulnerability.severity}`)
			//console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.createdAt}`)
			//console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.dismissedAt}`)
			//console.log(`${indent.join('')}${org}/${repo}: ${repoVulnerability.id}`)

			// Write the vulnerability to the file
			vulnFileLines.push(`${org}/${repo}\t${repoVulnerability.securityVulnerability.package.name}\t${repoVulnerability.securityVulnerability.advisory.summary}\t${repoVulnerability.securityVulnerability.severity}\t${repoVulnerability.createdAt}\t${repoVulnerability.dismissedAt}\t${repoVulnerability.id}`);
		}

		if (hasNextPage) {
			console.log('nextpage');
			pagination = getVulnResult.repository.vulnerabilityAlerts.pageInfo.endCursor;
		}

	} while (hasNextPage);

	// Generate summary lines
	let vulnFileLinesSummary = {};
	for (let line of vulnFileLines) {
		let packageName = line.split('\t')[1];
		let severity = line.split('\t')[3];
		let dismissedAt = line.split('\t')[5];

		if (!vulnFileLinesSummary[packageName]) {
			vulnFileLinesSummary[packageName] = {
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0
			};
		}

		if (dismissedAt === null) {
			if (severity === 'CRITICAL') {
				vulnFileLinesSummary[packageName].critical++;
			} else if (severity === 'HIGH') {
				vulnFileLinesSummary[packageName].high++;
			} else if (severity === 'MODERATE') {
				vulnFileLinesSummary[packageName].moderate++;
			} else if (severity === 'LOW') {
				vulnFileLinesSummary[packageName].low++;
			}
		}
	}

	for (let packageName in vulnFileLinesSummary) {
		let vulnCounts = vulnFileLinesSummary[packageName];
		let line = `${org}/${repo}\t${packageName}\t${vulnCounts.critical}\t${vulnCounts.high}\t${vulnCounts.moderate}\t${vulnCounts.low}`;
		vulnSummaryLines.push(line);
  }

  // Output summary lines
  //console.log(`${indent.join('')}${org}/${repo}: Vulnerability summary:`);
  //console.log(`${indent.join('')}${org}/${repo}: Package\tCritical\tHigh\tModerate\tLow`);
  //for (let line of vulnSummaryLines) {
  //  console.log(`${indent.join('')}${org}/${repo}: ${line}`);
  //}
}


const findDeps = async (org, repo) => {
	const query =
		`query ($org: String! $repo: String! $cursor: String){
		repository(owner: $org name: $repo) {
			name
			dependencyGraphManifests(first: 100 after: $cursor) {
			pageInfo {
				hasNextPage
				endCursor
			}
			
			nodes {
				dependenciesCount
				filename
				dependencies {
				nodes {
					packageManager
					packageName
					requirements
					hasDependencies
					repository {
						name
						owner {
							login
						}
						licenseInfo {
							name
							spdxId
							url
						}
					}
				}
				}
			}
			}
		}
	}`
		;
	let hasNextPage = false;
	do {
		console.log(`${indent.join('')}${org}/${repo}: Finding dependencies...`);

		if (checkedRepos.find(check => check.org == org && check.name == repo) != undefined) { // We've already checked this repo
			console.log(`${indent.join('')}${org}/${repo}: Already checked.`)
			return;
		}

		let getDepsResult = null;
		try {
			getDepsResult = await graphql({ query, org: org, repo: repo, cursor: pagination });
		}
		catch (e) {
			console.log(`${indent.join('')}${org}/${repo}: GraphQL query failed: ${e.message}`);
			return;
		}

		checkedRepos.push({
			"org": org,
			"name": repo
		});

		hasNextPage = getDepsResult.repository.dependencyGraphManifests.pageInfo.hasNextPage;
		const repoDependencies = getDepsResult.repository.dependencyGraphManifests.nodes;

		for (const repoDependency of repoDependencies) {
			console.log(`${indent.join('')}${org}/${repo}: ${repoDependency.dependenciesCount} dependencies found in ${repoDependency.filename}.`)
			for (const dep of repoDependency.dependencies.nodes) {
				console.log(`${indent.join('')}${org}/${repo} [${depth}]: Adding ${dep.packageName}`);
				fileLines.push(`${dep.packageName}\t${dep.requirements}\t${dep.packageManager}\t${repoDependency.filename}\t${org}/${repo}\t${(dep.repository != undefined && dep.repository.licenseInfo != undefined) ? dep.repository.licenseInfo.name : ''}\t${(dep.repository != undefined && dep.repository.licenseInfo != undefined) ? dep.repository.licenseInfo.spdxId : ''}\t${(dep.repository != undefined && dep.repository.licenseInfo != undefined) ? dep.repository.licenseInfo.url : ''}\t${dep.hasDependencies}`);
				if (dep.hasDependencies && dep.repository != undefined && depth < trans_depth) {
					try {
						console.log(`${indent.join('')}${org}/${repo}: ${dep.packageName} also has dependencies.  Looking up ${dep.repository.owner.login}/${dep.repository.name}...`);
						if (firstIndent) {
							indent.unshift(`|__[${depth}]: `);
						}
						else {
							//indent.shift();
							indent.unshift(`  `);
							indent.pop();
							indent.push(`|__[${depth}]: `);
						}
						depth++;
						firstIndent = false;
						await findDeps(dep.repository.owner.login, dep.repository.name);
						indent.shift();
						depth--;
					}
					catch (e) {
						console.log(`${indent.join('')}${org}/${repo}: Recusion request failed: ${e.message}`);
						console.log(e);
						depth--;
						indent.shift();
					}
				}
			}
		}

		if (hasNextPage) {
			console.log('nextpage');
			pagination = getDepsResult.repository.dependencyGraphManifests.pageInfo.endCursor;
		}

	} while (hasNextPage);
}

DumpDependencies();

async function DumpDependencies() {
	console.log(`############################################# header-row-fix ######################################################`)
	for (const repo of repoNames) {
		//Begin get depencies for one repo
		firstIndent = true;
		indent = [];
		depth = 0;
		try {
			const outfile = `./${org_name}-${repo}-dependency-list.csv`;
			console.log(`${indent.join('')}${org_name}/${repo}: Saving dependencies to ${outfile}...`);
			checkedRepos = [];
			vulnCheckedRepos = [];
			files.push(outfile);
			fileLines = [];
			vulnFileLinesSummary = [];
			vulnSummaryLines = [];
			headerRow = "packageName\tpackageVersion\tpackageEcosystem\tmanifestFilename\tmanifestOwner\tpackageLicenseName\tpackageLicenseId\tpackgeLicenseUrl\tpackageHasDependencies\tCriticalVulnerabilities\tHighVulnerabilities\tModerateVulnerabilities\tLowVulnerabilities\n";
			await findDeps(org_name, repo);

			await getVulnerabilityAlerts(org_name, repo);

			// For line in filelines, add SummaryLines if package name matches
			for (const line of fileLines) {
				console.log(`${indent.join('')}${org_name}/${repo}: Checking for vulnerabilities in ${line.split('\t')[0]}...`);
				let packageName = line.split('\t')[0];

				// Find a package name match in vulnSummaryLines
				let vulnSummaryLine = vulnSummaryLines.find(line => line.split('\t')[1] == packageName);

				if (vulnSummaryLine != undefined) {
					console.log(`${indent.join('')}${org_name}/${repo}: ${packageName} has vulnerabilities.  Adding to list...`);

					// Append vulnSummaryLine to the matched line in fileLines
					let newLine = line + '\t' + vulnSummaryLine.split('\t')[2] + '\t' + vulnSummaryLine.split('\t')[3] + '\t' + vulnSummaryLine.split('\t')[4] + '\t' + vulnSummaryLine.split('\t')[5];
					fileLines.splice(fileLines.indexOf(line), 1, newLine);
				} else {
					// Append empty vulnSummaryLine to the matched line in fileLines
					console.log(`${indent.join('')}${org_name}/${repo}: ${packageName} has no vulnerabilities.  Adding to list...`);
					let newLine = line + '\t' + '0' + '\t' + '0' + '\t' + '0' + '\t' + '0';
					fileLines.splice(fileLines.indexOf(line), 1, newLine);
				}
			}		
			
			console.log("Sorting...");

			let sorted = fileLines.sort((a, b) => {
				let packageA = a.split('\t')[4]; // manifest
				let packageB = b.split('\t')[4];

				if (packageA > packageB) {
					return 1;
				}
				else if (packageA < packageB) {
					return -1;
				}
				else {
					return 0;
				}
				});

			fs.writeFileSync(outfile, [headerRow, ...sorted].join('\n'));
			console.log(`${indent.join('')}${org_name}/${repo}: ${fileLines.length-2} items saved to ${outfile}`);
			// End get dependencies for one repo
		} catch (error) {
			console.log(`${indent.join('')}${org_name}/${repo}: Request failed:`, error.message);
		}
	}
	const uploadResponse = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, options);
}
