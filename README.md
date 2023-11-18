# RIPEMD-128

This repository contains two use cases of the RIPEMD-128 hash algorithm: file integrity check and user message integrity check. It also includes the external library `cryptopp` for cryptographic operations.

## Running the Program 

To execute the program, you will need a C++ compiler and after you've downloaded the project as a zip file, here are the steps to follow:

1. Extract the downloaded zip file.
2. Open the extracted folder in Visual Studio Code and install the C/C++ extension for Visual Studio Code. You can install the C/C++ extension by searching for 'C++' in the Extensions view.
3. Open the terminal through Visual Studio Code and write those commands: `cd cryptopp` and `make`, to compile the external library `cryptopp`
4. Modify the `tasks.json` file by adding this line `"-I", "${workspaceFolder}/cryptopp", "-L", "${workspaceFolder}/cryptopp", "-lcryptopp"`.
6. Run the program by pressing `F5`.
