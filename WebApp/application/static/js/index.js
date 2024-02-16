// Using a event listener to listen for the click event of the model description select option, determine what the user has selected and display the appropriate model description
document.addEventListener('DOMContentLoaded', function() {

    document.getElementById('model-select').addEventListener('change', function(){

        // Get the selected model
        var selectedModel = this.value

        var description = document.getElementById('model_description')
        switch(selectedModel) {
            case 'veggie_cnn_31x31':
                description.textContent = "A Convolutional Neural Network designed to process small-scale images with dimensions of 31 by 31 pixels. This model is specifically tailored for recognizing and classifying vegetables in images at a lower resolution. The smaller input size allows for faster processing, making it ideal for applications where computational efficiency is a priority."
                break;
            case 'veggie_cnn_128x128':
                description.textContent = "A detailed Convolutional Neural Network optimized to process high-resolution images with dimensions of 128 by 128 pixels. This model is capable of capturing more intricate details in images, making it suitable for applications where image quality is a priority. With a larger input size, this model can handle more complex images and is ideal for applications requiring a higher level of visual recognition process."
                break;
            default:
                description.textContent = "Select a model to view its description."
        }
    })
})

//Display images when images are uploaded
function displayImages(event){
    const fileInput = event.target;

    const uploadedImages = document.getElementById('preview-image');

    if (fileInput.files && fileInput.files[0]){
        const reader = new FileReader();

        reader.onload = function(e){
            uploadedImages.innerHTML = `<img src="${e.target.result}" alt="Uploaded Image" class="img-fluid" style="max-width: 100%; max-height: 100%;"/>`
        }

        reader.readAsDataURL(fileInput.files[0]);
    }
}

// Submit form when any input changes
const timestamp_filter = document.querySelector('#timestamp_filter');
const probabilty_filter = document.querySelector('#probability_filter');
const model_filter = document.querySelector('#model_filter')
const prediction_filter = document.querySelector('#prediction_filter')
const search_bar = document.querySelector('#search_bar');
const filterEntries = document.querySelector('#filterEntries');

timestamp_filter.addEventListener('change', () => {
    filterEntries.submit();
});

probabilty_filter.addEventListener('change', () => {
    filterEntries.submit();
});

model_filter.addEventListener('change', () => {
    filterEntries.submit();
});

prediction_filter.addEventListener('change', () => {
    filterEntries.submit();
})

search_bar.addEventListener('input', () => {
    filterEntries.submit();
});
