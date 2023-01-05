```

import tensorflow as tf

# Load the style transfer model.
model = tf.keras.applications.vgg19.VGG19(include_top=False, weights='imagenet')

# Define the loss and gradient functions.
@tf.function
def style_loss(outputs):
    style_outputs = model(style_image)
    style_loss = tf.add_n([tf.reduce_mean((outputs[name]-style_outputs[name])**2) for name in outputs.keys()])
    style_loss *= style_weight / num_style_layers
    return style_loss

@tf.function
def content_loss(outputs):
    return content_weight * tf.add_n([tf.reduce_mean((outputs[name]-content_outputs[name])**2) for name in outputs.keys()])

@tf.function
def total_loss(outputs):
    return style_loss(outputs) + content_loss(outputs)

# Define the optimization process.
optimizer = tf.optimizers.Adam(learning_rate=0.02, beta_1=0.99, epsilon=1e-1)

# Load the input image and style image.
input_image = tf.keras.preprocessing.image.load_img(input_image_path)
input_image = tf.keras.preprocessing.image.img_to_array(input_image)
input_image = tf.keras.applications.vgg19.preprocess_input(input_image)
input_image = tf.expand_dims(input_image, axis=0)

style_image = tf.keras.preprocessing.image.load_img(style_image_path)
style_image = tf.keras.preprocessing.image.img_to_array(style_image)
style_image = tf.keras.applications.vgg19.preprocess_input(style_image)
style_image = tf.expand_dims(style_image, axis=0)

# Extract features from the input image and style image.
outputs = model(input_image)
content_outputs = outputs
style_outputs = model(style_image)

# Initialize the loss and gradient variables.
style_loss = tf.zeros(shape=())
content_loss = tf.zeros(shape=())
total_loss = tf.zeros(shape=())

# Perform gradient descent.
for i in range(num_iterations):
    with tf.GradientTape() as tape:
        outputs = model(input_image)
        total_loss = total_loss(outputs)
    grads = tape.gradient(total_loss, model.trainable_variables)
    optimizer.apply_gradients(zip(grads, model.trainable_variables))

# Get the resulting image.
output_image = tf.keras.applications.vgg19.deprocess_input(input_image.numpy()[0])

# Save the output image.
tf.keras.preprocessing.image
```
