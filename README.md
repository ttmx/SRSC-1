To run the program navigate to the root of the repository and run the following commands:

```bash
gradlew installDist

java -cp "build\install\SRSC-1\lib\*" SignalServer

java -cp "build\install\SRSC-1\lib\*" hjStreamServer

java -cp "build\install\SRSC-1\lib\*" hjUDPproxy user password monsters
```

Works with Java 15 and above runtimes.