start_value = input("Enter the start number: ")
final_value = input("Enter the final number: ")
with open('number.txt','a') as file:
    for a in range(start_value,final_value):
        file.write("%i\n" %(a))
    file.close()
