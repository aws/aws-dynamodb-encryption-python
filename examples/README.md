# AWS DynamoDB Encryption SDK Examples

This section features examples that show you
how to use the AWS DynamoDB Encryption SDK.
We demonstrate how to use the encryption and decryption APIs
and how to set up some common configuration patterns.

## APIs

The AWS DynamoDB Encryption SDK provides four high-level APIs: `EncryptedClient`, `EncryptedItem`,
`EncryptedResource`, and `EncryptedTable`.

You can find examples that demonstrate these APIs
in the [`examples/src/dynamodb_encryption_sdk_examples`](./src/dynamodb_encryption_sdk_examples) directory. 
Each of these examples uses AWS KMS as the materials provider.

* [How to use the EncryptedClient API](./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_client.py)
* [How to use the EncryptedItem API](./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_item.py)
* [How to use the EncryptedResource API](./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_resource.py)
* [How to use the EncryptedTable API](./src/dynamodb_encryption_sdk_examples/aws_kms_encrypted_table.py)

## Configuration

To use the encryption and decryption APIs, you need to describe how you want the library to protect your data keys.
You can do this by configuring material providers. AWS KMS is the most common material provider used with the AWS DynamoDB Encryption
SDK, and each of the API examples above uses AWS KMS. This section describes the other providers that come bundled
with this library.

* [How to use the CachingMostRecentProvider](./src/dynamodb_encryption_sdk_examples/most_recent_provider_encrypted_table.py)
* [How to use raw symmetric wrapping keys](./src/dynamodb_encryption_sdk_examples/wrapped_symmetric_encrypted_table.py)
* [How to use raw asymmetric wrapping keys](./src/dynamodb_encryption_sdk_examples/wrapped_rsa_encrypted_table.py)

For more details on the different type of material providers, see [How to choose a cryptographic materials provider](https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/crypto-materials-providers.html).
