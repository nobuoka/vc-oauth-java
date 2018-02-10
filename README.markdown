vc-oauth-java
====================

Java library for [OAuth 1.0 Protocol](https://tools.ietf.org/html/rfc5849).

* Bintray repository (Releases) : https://bintray.com/nobuoka/maven/vc-oauth-java
* Artifactory repository (Snapshots) : https://oss.jfrog.org/artifactory/webapp/#/artifacts/browse/tree/General/oss-snapshot-local/info/vividcode/oauth

## For library developers

### How to publish snapshot to Artifactory repository

Use following command to publish snapshot to Artifactory repository:

```
./gradlew artifactoryPublish
```

Credentials for Artifactory must be provided by Gradle properties or environment variables.

```
artifactory.user_name={your Artifactory user name}
artifactory.api_key={your Artifactory api key}
```

```shell
export ARTIFACTORY_USER_NAME={your Artifactory user name}
export ARTIFACTORY_API_KEY={your Artifactory api key}
```
