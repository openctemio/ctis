# S3Scanner JSON lines mapping

Generated from `importer/spec_s3scanner.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `s3scanner`
- Source versions: S3Scanner 3.x -json (one log line per bucket, the bucket under "bucket")
- Fields: 15 mapped, 13 ignored on purpose (54% mapped)

## Rules

- A bucket that exists (exists 1) is a storage asset named by its provider's virtual-host name: aws <name>.s3.amazonaws.com, gcp <name>.storage.googleapis.com, digitalocean <name>.<region>.digitaloceanspaces.com, linode <name>.<region>.linodeobjects.com, scaleway <name>.s3.<region>.scw.cloud, dreamhost <name>.objects-us-east-1.dream.io, any other provider the bare name. A bucket that does not exist, or whose existence is unknown, is not kept.
- Each class of permission granted (value 1; 0 is denied, 2 unknown) is one misconfiguration finding on the bucket: anyone may write, change the ACL or has full control (s3scanner:public-write, critical); anyone may read or read the ACL (s3scanner:public-read, high); every authenticated user of the provider may write (s3scanner:authenticated-write, high) or read (s3scanner:authenticated-read, medium).
- A bucket is a candidate: the receiver keeps it as the organization's only when the organization already references that bucket, and holds every other bucket for review. Scanning names of other parties' buckets is the responsibility of the person who ran the tool.
- Object keys and the bucket owner's identity are never kept.
- Log lines without a bucket are read and ignored; a line that is not JSON is skipped and counted.
- Every bucket carries extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/bucket` | `assets[] (storage), findings[]` |  |
| `/bucket/name` | `assets[].value (with the provider's host form)` |  |
| `/bucket/provider` | `assets[].value host form, properties.storage_provider` |  |
| `/bucket/region` | `assets[].properties.region, value host form` |  |
| `/bucket/exists` | `only existing buckets are kept` |  |
| `/bucket/perm_all_users_read` | `findings[] s3scanner:public-read` |  |
| `/bucket/perm_all_users_read_acl` | `findings[] s3scanner:public-read` |  |
| `/bucket/perm_all_users_write` | `findings[] s3scanner:public-write` |  |
| `/bucket/perm_all_users_write_acl` | `findings[] s3scanner:public-write` |  |
| `/bucket/perm_all_users_full_control` | `findings[] s3scanner:public-write` |  |
| `/bucket/perm_auth_users_read` | `findings[] s3scanner:authenticated-read` |  |
| `/bucket/perm_auth_users_read_acl` | `findings[] s3scanner:authenticated-read` |  |
| `/bucket/perm_auth_users_write` | `findings[] s3scanner:authenticated-write` |  |
| `/bucket/perm_auth_users_write_acl` | `findings[] s3scanner:authenticated-write` |  |
| `/bucket/perm_auth_users_full_control` | `findings[] s3scanner:authenticated-write` |  |
| `/bucket/date_scanned` |  | scan time; the report time is kept |
| `/bucket/objects` |  | object keys can be personal or secret data: never kept |
| `/bucket/objects[]` |  | object keys can be personal or secret data: never kept |
| `/bucket/objects[]/**` |  | object keys can be personal or secret data: never kept |
| `/bucket/objects_enumerated` |  | whether objects were listed |
| `/bucket/num_objects` |  | object count |
| `/bucket/bucket_size` |  | total size |
| `/bucket/owner_id` |  | the owner's identity at the provider: personal data of another party |
| `/bucket/owner_display_name` |  | the owner's identity at the provider: personal data of another party |
| `/bucket/ID` |  | S3Scanner's database row id |
| `/level` |  | log level |
| `/msg` |  | log message |
| `/time` |  | log time |
