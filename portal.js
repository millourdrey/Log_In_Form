document.querySelectorAll(".academic-form").forEach(function (form) {
    const classSelect = form.querySelector(".class-picker");
    const studentSelect = form.querySelector(".student-picker");
    if (!classSelect || !studentSelect) return;

    const options = Array.from(studentSelect.options);
    function filterStudents() {
        const matching = options.filter(function (option) {
            return option.dataset.class === classSelect.value;
        });
        studentSelect.replaceChildren(...matching.map(function (option) {
            return option.cloneNode(true);
        }));
        studentSelect.disabled = matching.length === 0;
    }

    classSelect.addEventListener("change", filterStudents);
    filterStudents();
});

document.querySelectorAll(".delete-account-form").forEach(function (form) {
    form.addEventListener("submit", function (event) {
        const confirmed = window.confirm(
            "Permanently delete this account? Associated class, attendance, and grade records may also be deleted. This cannot be undone."
        );
        if (!confirmed) event.preventDefault();
    });
});
