document.addEventListener("DOMContentLoaded", function () {
  const checkbox = document.querySelector(".theme-switch__checkbox");
  const navMenu = document.querySelector(".nav_menu");

  // Function to toggle dark mode
  function toggleDarkMode(darkMode) {
    document.body.classList.toggle("dark-mode", darkMode);
    if (darkMode) {
      localStorage.setItem("darkMode", "true");
    } else {
      localStorage.removeItem("darkMode");
    }
  }
  //scroll me blurr and stickey  asiba//
  window.addEventListener('scroll', function() {
    const header = document.querySelector('header');
    const scrollPosition = window.scrollY;

    if (scrollPosition > 0) {
        header.classList.add('sticky-header');
    } else {
        header.classList.remove('sticky-header');
    }
});

  //scroll me shadow  asiba//
  window.onscroll = function() {headerShadow()};
 
  function headerShadow() {
    const navHeader =document.getElementById("myHeader");

    if (document.body.scrollTop > 50 || document.documentElement.scrollTop > 50) {

      navHeader.style.boxShadow = "0 1px 6px rgba(0, 0, 0, 0.1)";
      navHeader.style.height="70px";
      navHeader.style.lineHeight = "70px";
    } else {

      navHeader.style.boxShadow = "none";
      navHeader.style.height="70px";
      navHeader.style.lineHeight = "70px";
    }
  }

  // Check local storage for dark mode preference//
  const storedDarkMode = localStorage.getItem("darkMode");
  if (storedDarkMode === "true") {
    checkbox.checked = true;
    toggleDarkMode(true);
  }

  // Toggle dark mode when checkbox changes
  checkbox.addEventListener("change", function () {
    toggleDarkMode(this.checked);
  });

  // Toggle menu display
  const menuToggle = document.querySelector(".menu-toggle");
  menuToggle.addEventListener("click", () => {
    navMenu.classList.toggle("display-menu");
  });
});

/*===== typing effect ======*/
var typingEffect = new Typed(".typedText", {
  strings: ["Designer", "Programmer", "Freelancer", "Web Developer", "Engineer", "Architect"],
  loop: true,
  typeSpeed: 100,
  backSpeed: 80,
  backDelay: 2000,
});

// scroll reveal animation
const sr = ScrollReveal({
  origin:'top',
  distance: '80px',
  duration: 2000,
  reset: true
})
//home
sr.reveal('.logo',{})
  sr.reveal('.hero-work',{delay: 100})
  sr.reveal('.hero-description',{delay: 200})
  sr.reveal('.hero-buttons',{delay: 200})
  sr.reveal('.hero-social-icons',{delay: 200})
  sr.reveal('.col col-l',{delay: 300})

// project animation
sr.reveal('.top-header',{interval: 200})

// header
sr.reveal('.top-header',{})

// about info
const srLeft = ScrollReveal({
  origin:'left',
  distance: '80px',
  duration: 2000,
  reset: true
})

srLeft.reveal('.about-info',{delay : 100})
srLeft.reveal('.contact-info',{delay : 100})

//skill box
const srRight = ScrollReveal({
  origin:'right',
  distance: '80px',
  duration: 2000,
  reset: true
})

srRight.reveal('.skills-box',{delay : 100})
srRight.reveal('.form-control',{delay : 100})

// proect animation when scroll
function isInView(element) {
  const rect = element.getBoundingClientRect();
  return (
      rect.top >= 0 &&
      rect.left >= 0 &&
      rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
      rect.right <= (window.innerWidth || document.documentElement.clientWidth)
  );
}

// Function to handle scroll event
const sections = document.querySelectorAll('section[id]')
  function scrollActive() {
    const scrollY = window.scrollY;
    sections.forEach(current =>{
      const sectionHeight = current.offsetHeight,
          sectionTop = current.offsetTop - 50,
        sectionId = current.getAttribute('id')
      if(scrollY > sectionTop && scrollY <= sectionTop + sectionHeight) { 
          document.querySelector('.nav-menu a[href*=' + sectionId + ']').classList.add('active-link')
      }  else {
        document.querySelector('.nav-menu a[href*=' + sectionId + ']').classList.remove('active-link')
      }
    })
  }
  window.addEventListener('scroll', scrollActive)


// automatically count
const counts = document.querySelectorAll('.count')
const speed = 80

counts.forEach((counter) => {
    function upDate(){
        const target = Number(counter.getAttribute('data-target'))
        const count = Number(counter.innerText)
        const inc = target / speed        
        if(count < target){
            counter.innerText = Math.floor(inc + count) 
            setTimeout(upDate, 18)
        }else{
            counter.innerText = target+' %'
        }
    }
    upDate()
})
