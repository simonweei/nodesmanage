const form = document.querySelector("#login-form");
const errorBox = document.querySelector("#login-error");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  errorBox.textContent = "";
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: new FormData(form).get("password") }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "登录失败");
    location.replace("/");
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
