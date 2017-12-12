start_value = input("Enter the start number: ")
Final_value = input("Enter the final number: ")
with open('number.txt','a') as file:
    for a in range(start_value,Final_value):
        file.write("%i\n" %(a))
    file.close()
