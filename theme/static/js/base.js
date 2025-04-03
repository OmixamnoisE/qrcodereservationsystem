document.getElementById('loginButton')?.addEventListener('click', function() {
    document.getElementById('loginModal').classList.remove('hidden');
  });
  
  document.getElementById('closeLoginModal')?.addEventListener('click', function() {
    document.getElementById('loginModal').classList.add('hidden');
  });
  
  const profileImage = document.getElementById("profileImage");
  const editProfileModal = document.getElementById("editProfileModal");
  const closeEditProfileModal = document.getElementById("closeEditProfileModal");
  
  if (profileImage) {
    profileImage.addEventListener("click", function() {
      editProfileModal.classList.remove("hidden");
    });
  
    closeEditProfileModal.addEventListener("click", function() {
      editProfileModal.classList.add("hidden");
    });
  }
  
  document.addEventListener("DOMContentLoaded", function() {
    const loader = document.getElementById("globalLoader");
  
    // Function to show loader and navigate
    const showLoaderAndNavigate = (url) => {
      loader.classList.remove("hidden");
      setTimeout(() => {
        window.location.href = url;
      }, 300); // Delay to ensure loader is visible
    };
  
    // Show loader on internal link clicks
    document.querySelectorAll("a").forEach(link => {
      link.addEventListener("click", function(event) {
        const url = link.getAttribute("href");
  
        if (!url || url.startsWith("#") || url.startsWith("http")) return;
  
        event.preventDefault(); // Prevent immediate navigation
        showLoaderAndNavigate(url);
      });
    });
  
    // Show loader on form submission
    document.querySelectorAll("form").forEach(form => {
      form.addEventListener("submit", () => {
        loader.classList.remove("hidden");
      });
    });
  
    // Hide loader when the page is fully loaded
    window.addEventListener("load", () => {
      loader.classList.add("hidden");
    });
  
    // Handle browser cache behavior
    window.addEventListener("pageshow", (event) => {
      if (event.persisted) {
        loader.classList.add("hidden");
      }
    });
  });
  