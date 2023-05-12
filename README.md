
## steps:

- prepare ec2 instance

    - with enclave enable
    - create kms, generate key and modify kmsConfig info in file `test/ec2Client/ec2Client.go`
    - if test in prod mode, should set kms access policy

- run enclave server

    - debug mode: 

    ```
    (./nitro-toolkit/test/enclaveServer/buildEnclaveAndRunOnEC2_debug.sh > enclaveServer.logs 2>&1 &)
    ```

    - prod mode:

    ```
    (./nitro-toolkit/test/enclaveServer/buildEnclaveAndRunOnEC2.sh > enclaveServer.logs 2>&1 &)
    ```

- run ec2 client

    - one time to verify
    ```
    (./nitro-toolkit/test/ec2Client/buildClientAndRunOnEC2.sh > ec2Client.logs 2>&1 &)
    ```

    - stress test to check the stability
    ```
    (./nitro-toolkit/test/ec2Client/buildClientAndRunOnEC2_stress.sh > ec2Client.logs 2>&1 &)
    ```