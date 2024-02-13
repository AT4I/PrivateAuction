import subprocess

# Define the command-line arguments for myprogram.go
#    num-iterations(typically 5 - maybe higher for low key sizes, and low message space),
#    key-bits (256-2048)
#    message space (order of millions to trillion for large key size)
#    number of bidders (2-128 - larger numbers for smaller key size)
#    max rand - relative to bit value / message space
#    max bid value 
#    rng seed for simulation
args = [
    [5, 512, 10000000000, 5, 10000, 100000, 76],
    [5, 512, 10000000000, 10, 10000, 100000, 76],
    [5, 512, 10000000000, 15, 10000, 100000, 76],
    [5, 512, 10000000000, 20, 10000, 100000, 76],
    [5, 512, 10000000000, 40, 10000, 100000, 76],
]

# Loop through the arguments and run your Go program for each set of arguments
for arg_set in args:
    # Construct the command to run the Go program with the current set of arguments
    cmd = [
        'go', 'run', 'test1.go',
        str(arg_set[0]), str(arg_set[1]), str(arg_set[2]), str(arg_set[3]),
        str(arg_set[4]), str(arg_set[5]), str(arg_set[6])
    ]
    
    # Run the command and capture the output
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Print the output
    print(result.stdout)

