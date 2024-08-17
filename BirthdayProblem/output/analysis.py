import matplotlib.pyplot as plt
import csv

with open('output.csv', newline='') as csv_file:
    reader = csv.DictReader(csv_file)
    percentage_threshold = 10
    x_axis = []
    y_axis = []
    for row in reader:
        row_percentage_threshold = row['Percentage Threshold']
        if (row_percentage_threshold != percentage_threshold):
            plt.plot(x_axis, y_axis, '0')
        

        print(row['Hash Number'], row['Domain Space'])
