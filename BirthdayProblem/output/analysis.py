import matplotlib.pyplot as plt
from matplotlib import ticker
import numpy as np
import csv

# plot domain vs hash number based on percentage number
with open('output.csv', newline='') as csv_file:
    reader = csv.DictReader(csv_file)
    percentage_threshold = "10"
    x_axis = []
    y_axis = []
    fig, ax = plt.subplots()
    ax.ticklabel_format(axis='y', style='plain')
    ax.yaxis.set_major_locator(ticker.MaxNLocator(20))
    for row in reader:
        row_percentage_threshold = row['Percentage Threshold']
        if (row_percentage_threshold != percentage_threshold):
            ax.plot(x_axis, y_axis, label=percentage_threshold)
            x_axis = []
            y_axis = []
            percentage_threshold = row_percentage_threshold
        x_axis.append(int(row['Domain Space']))
        y_axis.append(int(row['Hash Number']))
    ax.set_xlabel("Domain Space (2**N)")
    ax.set_ylabel("Hash number above line percentage")
    ax.legend()
    plt.show()
    

#plot hash number vs percentage threshold  based on domain space

rows = []
with open('output.csv', newline='') as csv_file:
    reader = csv.DictReader(csv_file)
    for row in reader:
        rows.append(row)

fig, ax = plt.subplots()
ax.ticklabel_format(axis='y', style='plain')
ax.yaxis.set_major_locator(ticker.MaxNLocator(20))
ax.set_xlabel("Percentage Threshold")
ax.set_ylabel("Hash number above line percentage")

for i in range(10, 51):
    domain_space = i
    x_axis = []
    y_axis = []
    for row in rows:
        row_Domain_Space = int(row['Domain Space'])
        if (row_Domain_Space == domain_space):
            x_axis.append(int(row['Percentage Threshold']))
            y_axis.append(int(row['Hash Number']))

    ax.plot(x_axis, y_axis, label=domain_space)

ax.legend()
plt.show()

# in order to find the model of best fit, we need to do some math.
# we're going to use numpy for this, but we could do it by hand. 
# we first need to gather the data again as in part 1, and then do a polyfit according to log(y) which transforms the
# data into a 'linear' model. once we have this we can convert it back to an exponential equation
# we can then ask it to 'guess' how many hashes it would take to find a colision at the given threshold for the given
# hash bit sizes.

with open('output.csv', newline='') as csv_file:
    reader = csv.DictReader(csv_file)
    percentage_threshold = "10"
    x = []
    y = []
    a_b = []
    for row in reader:
        row_percentage_threshold = row['Percentage Threshold']
        if (row_percentage_threshold != percentage_threshold):
            p = np.polyfit(x, np.log(y), 1)
            a = np.exp(p[1])
            b = p[0]
            # y = A * e^(B * x) + C (c is 0)
            a_b.append({ "a": a,
                        "b": b,
                        "percentage": percentage_threshold})

            x = []
            y = []
            percentage_threshold = row_percentage_threshold
        x.append(int(row['Domain Space']))
        y.append(int(row['Hash Number']))



    hash_lengths = [64, 128, 192, 256, 384, 512]
    for length in hash_lengths:
        for i in range(0, len(a_b)):
            hash_number = a_b[i]['a'] * np.exp(a_b[i]['b'] * length)
            between_power = 1
            while (hash_number > 2**between_power):
                between_power += 1
            print(f"A hash with a length of {length} will find a collision at {a_b[i]['percentage']}% threshold. This is hash number {hash_number:,.1f}")
            print(f"\tThis is a resulting bit-strength between 2^{between_power - 1} and 2^{between_power}")
            
            # From here we can do even more math. 

            # there are approximately 2 billion computers in the world. Let's assume that on average, the general
            # computer could generate 10,000,000,000 (10 billion) hashes a second. If this is the case. how many years
            # will it take to break hashes of these lengths?
            number_of_computers = 2000000000
            number_of_hash_per_computer = 10000000000 
            number_of_computations_in_year = 365 * 24 * 60 * 60 * number_of_hash_per_computer * number_of_computers
            num_of_years = hash_number / number_of_computations_in_year
            time_reference = "years"
            computers = "all computers"
            if (num_of_years < 1):
                num_of_years *= 365
                time_reference = "days"
                if (num_of_years < 1):
                    num_of_years *= 24
                    time_reference = "hours"
                    if (num_of_years < 1):
                        num_of_years *= 60
                        time_reference = "minutes"
                        if (num_of_years < 1):
                            num_of_years *= 60
                            time_reference = "seconds"
            print(f"\tIt will take {num_of_years:,.1f} {time_reference} for all computers in the world to find a hash collision at this level.")
            num_of_years *= number_of_computers
            print(f"\tIt will take one computer {num_of_years:,.1f} {time_reference}")
            print("")
        print("")