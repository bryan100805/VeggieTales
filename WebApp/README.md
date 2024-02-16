# README
This project aim to develop a Deep Learning Web application that is able to predict the vegetable classes based on the images uploaded and the model selected (i.e. CNN 31x31 and CNN 128x128) by the users.
The result of the prediction will produce these columns in the form of a history table:
 
1. Entry ID
2. Image
3. Model (CNN 31x31 or CNN 128x128)
4. Prediction (15 classes):
    - e.g. ["Bean", "Bitter Gourd", "Bottle Gourd", "Brinjal", "Broccoli", "Cabbage", "Capsicum", "Carrot", "Cauliflower", "Cucumber", "Papaya", "Potato", "Pumpkin", "Radish", "Tomato"]
5. Probability (Max C.I of the prediction)
6. Timestamp (SG time)

Users are also able to view specific records through searching and filtering of values. They are able to filter based on timestamps and accuracy in ascending and descending manner, choose records that fall in certain predictions and models used to predict them. This project has been using DevOps methodology to boost the productivity through CI/CD. 