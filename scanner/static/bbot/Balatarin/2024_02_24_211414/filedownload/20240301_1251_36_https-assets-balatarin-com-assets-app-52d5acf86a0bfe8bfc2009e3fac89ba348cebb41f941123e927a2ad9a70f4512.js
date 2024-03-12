const getRecaptchaToken = () => {
  return new Promise((resolve, reject) => {
    try {
      if (window.grecaptcha && typeof window.grecaptcha.execute === "function") {
        grecaptchaExecute(window.grecaptcha.execute);
      } else {
        window.grecaptcha.ready(async () => {
          grecaptchaExecute(window.grecaptcha.execute);
        });
      }

      // grecaptcha execute action
      async function grecaptchaExecute(ExecuteAction) {
        const captchaToken = await ExecuteAction(
          xxxxxx, // my recaptcha site key
         
        );
        return resolve(captchaToken);
      }
    } catch (error) {
      return reject(error);
    }
  });
};