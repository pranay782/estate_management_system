document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".flash").forEach(el => {
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transform = "translateY(-8px)";
      setTimeout(() => el.remove(), 400);
    }, 4200);
  });

  document.querySelectorAll("form[onsubmit]").forEach(form => {
    form.addEventListener("submit", e => {
      const result = form.getAttribute("onsubmit");
      if (result && !confirm("Are you sure?")) e.preventDefault();
    });
  });
});
