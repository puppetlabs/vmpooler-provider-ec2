# vmpooler-provider-aws

- [vmpooler-provider-aws](#vmpooler-provider-aws)
  - [Usage](#usage)
    - [Provisioning the new nodes](#provisioning-the-new-nodes)
    - [DNS](#dns)
    - [Labels](#labels)
    - [Pre-requisite](#pre-requisite)
  - [Update the Gemfile Lock](#update-the-gemfile-lock)
  - [Releasing](#releasing)
  - [License](#license)

This is a provider for [VMPooler](https://github.com/puppetlabs/vmpooler) allows using aws to create instances, disks,
snapshots, or destroy instances for specific pools.

## Usage

Include this gem in the same Gemfile that you use to install VMPooler itself and then define one or more pools with the `provider` key set to `aws`. VMPooler will take care of the rest.
See what configuration is needed for this provider in the [example file](https://github.com/puppetlabs/vmpooler-provider-aws/blob/main/vmpooler.yaml.example).

Examples of deploying VMPooler with extra providers can be found in the [puppetlabs/vmpooler-deployment](https://github.com/puppetlabs/vmpooler-deployment) repository.

aws authorization is handled via two required ENV vars

1. ABS_AWS_ACCESS_KEY
2. ABS_AWS_SECRET_KEY

### Provisioning the new nodes

When you add the pool config `provision: true` to a pool, the new VMs will also get initialized with extra steps to setup the sshd config via NET:SSH
These steps expect two environment vars
1. ROOT_KEYS_SCRIPT: (optional) the URI location of a script (eg https in github) that will be run to setup keys. If not set, this will be skipped
2. AWS_KEY_FILE_LOCATION: (required) the location on local disk where the ssh key resides for VMPooler to connect via SSH to the EC2 node

### DNS
AWS will setup a private ip and private dns hostname for the VM once running. Optionally we can setup a human readable DNS entry to resolve the VMPooler provider `spicy-proton` fqdn

DNS is integrated via Google's CloudDNS service.
GCE authorization is handled via a service account (or personal account) private key (json format) and can be configured via

1. GOOGLE_APPLICATION_CREDENTIALS environment variable eg GOOGLE_APPLICATION_CREDENTIALS=/my/home/directory/my_account_key.json

Provider config needed:
1. domain
2. project
3. dns_zone_resource_name
(see the example yaml file)

An A record is then created in that zone upon instance creation with the VM's internal IP, and deleted when the instance is destroyed.

### Labels
This provider adds tags to all resources that are managed

|resource|labels|note|
|---|---|---|
|instance|vm=$vm_name, pool=$pool_name|for example vm=foo-bar, pool=pool1|
|disk|vm=$vm_name, pool=$pool_name|for example vm=foo-bar and pool=pool1|
|snapshot|snapshot_name=$snapshot_name, vm=$vm_name, pool=$pool_name| for example snapshot_name=snap1, vm=foo-bar, pool=pool1|

Also see the usage of vmpooler's optional purge_unconfigured_resources, which is used to delete any resource found that
do not have the pool label, and can be configured to allow a specific list of unconfigured pool names. 

### Pre-requisite

- An IAM user must exist in the target AWS account with permissions to create, delete vms etc
- if using DNS see section above, and a service account with permissions to change Cloud DNS need to exist

## Update the Gemfile Lock

To update the `Gemfile.lock` run `./update-gemfile-lock`.

Verify, and update if needed, that the docker tag in the script and GitHub action workflows matches what is used in the [vmpooler-deployment Dockerfile](https://github.com/puppetlabs/vmpooler-deployment/blob/main/docker/Dockerfile).

## Releasing

Follow these steps to publish a new GitHub release, and build and push the gem to <https://rubygems.org>.

1. Bump the "VERSION" in `lib/vmpooler-provider-ec2/version.rb` appropriately based on changes in `CHANGELOG.md` since the last release.
2. Run `./update-gemfile-lock` to update `Gemfile.lock`.
3. Run `./update-changelog` to update `CHANGELOG.md`.
4. Commit and push changes to a new branch, then open a pull request against `main` and be sure to add the "maintenance" label.
5. After the pull request is approved and merged, then navigate to Actions --> Release Gem --> run workflow --> Branch: main --> Run workflow.

## License

vmpooler-provider-aws is distributed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html). See the [LICENSE](LICENSE) file for more details.