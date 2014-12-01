sss
===

This library contains Java implementation of the [Shamir's Secret Sharing](http://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) algorithm.

You can use it to split arbitrary data into a number of shares.
In order to join shares back into the secret data, certain, minimum number of shares must be present.
The library contains utlity functions for serializing and de-serializing shares into binary messages, for compact and easy storing and sharing.

Artifacts are available in Maven Central repository at the following coordinates:

    <dependency>
        <groupId>rs.in.zivanovic</groupId>
        <artifactId>sss</artifactId>
        <version>1.0.0</version>
    </dependency>
