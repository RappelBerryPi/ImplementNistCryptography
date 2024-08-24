import matplotlib.pyplot as plt
from matplotlib import ticker
import csv

with open('output.csv', newline='') as csv_file:
    reader = csv.DictReader(csv_file)
    percentage_threshold = "10"
    x_axis = []
    y_axis = []
    for row in reader:
        row_percentage_threshold = row['Percentage Threshold']
        if (row_percentage_threshold != percentage_threshold):
            plt.plot(x_axis, y_axis)
            plt.autoscale(True)
            x_axis = []
            y_axis = []
            percentage_threshold = row_percentage_threshold
            plt.show()
        x_axis.append(row['Domain Space'])
        y_axis.append(row['Hash Number'])
    
