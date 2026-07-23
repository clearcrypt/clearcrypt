import { readFileSync } from "node:fs";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
);
const releaseTag = process.env.RELEASE_TAG ?? process.argv[2];
const expectedTag = `v${packageJson.version}`;

if (!releaseTag) {
  throw new Error("Set RELEASE_TAG or pass the Git tag as an argument");
}
if (releaseTag !== expectedTag) {
  throw new Error(
    `Release tag ${JSON.stringify(releaseTag)} does not match package version ${JSON.stringify(expectedTag)}`
  );
}

console.log(`Verified release tag ${releaseTag}`);
