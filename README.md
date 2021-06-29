# CrowdStrike environment replicator

This tool uses the CrowdStrike API to read and write policies, rules, exclusions, etc. from and to CrowdStrike environments.

It implements API methods for the following CrowdStrike elements:
* Host groups
* Custom IOA rules
* Device (USB) control policies
* Indicators of compromise *(incomplete)*
* Machine learning exclusions
* Prevention policies
* IOA exclusions *(incomplete)*
* Sensor update policies
* Sensor visibility exclusions 

The tool uses the construct of **source** and **target** API clients. **Source** API clients represent the clients and associated environments from which the tool **reads** data. **Target** API clients represent clients and associated environments to which the tool **writes**. This allows API clients to be tightly scoped with read and write privileges. This means that even when reading from and writing to the same environment (such as with the `wipe` module), you need to specify **source** and **target** API credentials. These could belong to separate API clients with read and write privileges respectively, or one API client with read and write privileges.

The tool has four modules: 
* backup *(incomplete)*
* replicate - Copy groups, policies, rules, exclusions, etc. from source environment to target environment.
* restore *(incomplete)*
* wipe - Remove groups, policies, rules, exclusions, etc. from target environment.

The backup and restore modules are incomplete, but the "scaffolding" to implement the modules, and most if not all required class methods, exist in the code base.


**Usage:**

Usage requires the appropriately scoped API client IDs and secrets. Ensure the provisioned API clients are scoped with the appropriate permissions to prevent unwanted changes to an environment.

Generally speaking, CrowdStrike users require the "Falcon Administrator" role in order to create API clients.

Run `replicator.py` specifying one of the `replicate` or `wipe` modules and a path to your configuration file with the `-c` or `--config` argument:

`python3 replicator.py replicate -c /path/to/replicate/config`

`python3 replicator.py wipe -c /path/to/wipe/config`

The configuration file includes entries for the different API clients, as well as a list of API methods to be called. Set the API method to `True` for the script to attempt to replicate or wipe that element of the source environment. Set it to `False` to skip that element of replication or wiping.

The operator can choose to leave the API client IDs and secrets blank in the configuration file. The script looks for API client IDs and secrets in the following order:
1. Provided via command line arguments `-sI / --source-id`, `-sS / --source-secret`, `-tI / --target-id`, `-tS / --target-secret`
2. Included in the config file
3. As OS environment variables `CS_SOURCE_ID`, `CS_SOURCE_SECRET`, `CS_TARGET_ID`, `CS_TARGET_SECRET`
4. Through interactive command prompts using the `getpass` library

The intent is for the operator to be able to mix and match these methods. For example by storing the client ID in the configuration file but providing the client secret via interactive command prompt.

By default, prevention policies written to a target environment are in a disabled state. Enabling policies requires an additional API call. To automatically enable policies written to a target environment, pass the `-e / --enable` argument when running the `replicate` module.

Similarly, enabled policies cannot be deleted. To automatically disable policies so that they can be removed, pass the `-d / --disable` parameter to the `wipe` module. This does not apply to default policies, which cannot be removed.

The tool also has proxy support via the `proxy` line in the configuration file. Enter proxy information in the format IP:port, such as `127.0.0.1:8080`. Do not include a protocol schema. Note that the tool **disables certificate verification** when using a proxy, though this could be changed. 


**Known issues:** 

* The API does not honor the enabled state (enabled or disabled) of policies and rules - thy default to disabled when copied between environments.
* Writing indicators of compromise (IOCs) fails for unknown reasons. POST requests return a 201 but IOCs do not appear in target environment.
* The IOA exclusion writing endpoint returns a 405 ("method not allowed") with HTTP POST requests, despite documentation of this method.
* While the script replicates rules, policies, and exclusions, some manual review and follow-up is still necessary. This includes:
  * Enabling policies, rules, etc.
  * Setting precedence.
  * Assigning policies to groups.  

