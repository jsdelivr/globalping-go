const { readFileSync, writeFileSync } = require("node:fs");

const repositoryModulePath = "github.com/jsdelivr/globalping-go";
const version = process.argv[2] ?? "";
const versionMatch = /^v?(\d+)\./.exec(version);

const fail = (message) => {
	writeFileSync(1, `${message}\n`);
	process.exit(1);
};

if (!versionMatch) {
	fail(`Unable to determine the major version from proposed release ${JSON.stringify(version)}.`);
}

let goMod;

try {
	goMod = readFileSync("go.mod", "utf8");
} catch (error) {
	fail(`Unable to read go.mod: ${error.message}`);
}

const moduleMatch = /^module\s+(\S+)\s*$/m.exec(goMod);

if (!moduleMatch) {
	fail("Unable to find the module directive in go.mod.");
}

const major = Number(versionMatch[1]);
const expectedModulePath = major >= 2
	? `${repositoryModulePath}/v${major}`
	: repositoryModulePath;

if (moduleMatch[1] !== expectedModulePath) {
	fail(
		`Release ${version} requires the go.mod module path ${expectedModulePath}, `
		+ `but found ${moduleMatch[1]}. Migrate the module path and imports before releasing.`,
	);
}
