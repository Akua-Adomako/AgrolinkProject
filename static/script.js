
    function handleContactSubmit(event) {
        event.preventDefault(); // Prevent the form from submitting traditionally

        // Optional: Validate the form inputs if needed
        const name = document.getElementById('name').value.trim();
        const email = document.getElementById('email').value.trim();
        const subject = document.getElementById('subject').value.trim();
        const message = document.getElementById('message').value.trim();

        if (!name || !email || !subject || !message) {
            alert('Please fill out all fields.');
            return;
            }

        // Show a success message
        const successMessage = document.getElementById('success-message');
        successMessage.classList.remove('d-none');

        // Optionally, reset the form
        document.getElementById('contact-form').reset();
    }
