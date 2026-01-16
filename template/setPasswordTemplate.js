const logoURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346150/email-assets/hzcl6heksswnumx0dpvj.jpg";
const bgURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346154/email-assets/lfyph07cneblr6u4eyea.png";
const instaURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346147/email-assets/tk4elrj17odvckohcphj.png";
const linkedinURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346149/email-assets/ly2cuolsv8left1tc1uv.png";
const image1URL="https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346145/email-assets/nzblte27m1nyadkffxh8.png"
const image2URL="https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346151/email-assets/ex1lfshnofxjigm4y2zb.jpg"


// const setPasswordTemplate = async (link) => {
//   try {
//     const html = `              
//             <body style="margin:0; padding:0; font-family: Arial, Helvetica, sans-serif; overflow:hidden;">

//               <div style="
//                   position: fixed;
//                   top: 0; left: 0;
//                   width: 100%; height: 100vh;
//                   display: flex;
//                   justify-content: center;
//                   align-items: center;
//                   background-image: url('${bgURL}');
//                   background-size: cover;
//                   background-position: center;
//                   background-repeat: no-repeat;
//               ">

//                 <div style="
//                     background: white;
//                     max-width: 600px;
//                     width: 100%;
//                     border-radius: 12px;
//                     padding: 40px 30px;
//                     text-align: center;
//                 ">

//                   <img src="${logoURL}" alt="Logo" style="
//                       width: 170px;
//                       margin: 0 auto;
//                       display: block;
//                       object-fit: contain;
//                   " />

//                   <img src="${image2URL}" alt="set Illustration" style="
//                       width: 60%;
//                       margin-top: 15px;
//                   " />

//                   <h3 style="
//                       font-size: 24px;
//                       font-weight: 700;
//                       color: #3a5fbe;
//                       margin-bottom: 5px;
//                   ">Set your password</h3>

//                   <p style="
//                       font-size: 15px;
//                       color: black;
//                       margin-top: 0;
//                       margin-bottom: 10px;
//                       line-height: 1.5;
//                   ">
//                     Let's make your account more secure and safe.
//                   </p>

//                   <a href="${link}" style="text-decoration:none;">
//                     <button style="
//                         background: #1949c2;
//                         color: #fff;
//                         padding: 12px 28px;
//                         border: none;
//                         border-radius: 6px;
//                         font-weight: 600;
//                         cursor: pointer;
//                         margin-top: 10px;
//                     ">
//                       SET PASSWORD
//                     </button>
//                   </a>

//                   <p style="
//                       margin-bottom: 0;
//                       margin-top: 8px;
//                       font-size: 10px;
//                       color: #666;
//                   ">
//                     <img src="${logoURL}" alt="Logo" style="
//                         width: 50px;
//                         height: 13px;
//                         vertical-align: middle;
//                         margin-right: 4px;
//                     " />
//                     © • <span style="text-decoration: underline; cursor: pointer;">Unsubscribe</span>
//                   </p>

//                   <hr style="
//                       border: none;
//                       border-top: 1px solid #3a5fbe;
//                       margin-top: 10px;
//                       margin-bottom: 0;
//                       width: 100%;
//                   " />

//                   <p style="
//                       font-size: 11px;
//                       color: #333333;
//                       margin-bottom: 2px;
//                       margin-top: 10px;
//                   ">
//                     By setting a password, you help protect your account and personal information.<br/>
//                     ITI Rd, Aundh, Pune / www.creativewebsolution.in / (+91) 9326246981
//                   </p>

//                   <div style="margin-top: 5px;">
//                     <a href="https://www.instagram.com/creativewebsolution99/" target="_blank">
//                       <img src="${instaURL}" alt="Instagram" style="width: 28px; margin: 5px 10px; cursor: pointer;" />
//                     </a>

//                     <a href="https://www.linkedin.com/company/creativewebsolution404/" target="_blank">
//                       <img src="${linkedinURL}" alt="LinkedIn" style="width: 28px; margin: 5px 10px; cursor: pointer; height: 25px;" />
//                     </a>
//                   </div>

//                 </div>

//               </div>

//             </body>  
//     `;

//     return html;

//   } catch (error) {
//     console.error(` Error generating email template: ${error.message}`);
//     throw new Error("Template generation failed");
//   }
// };

// module.exports = setPasswordTemplate;

const setPasswordTemplate = async (link) => {
  try {
    const html = `
    <body style="margin:0; padding:0; font-family: Arial, Helvetica, sans-serif; background:#f4f4f4;">

  <!-- 100% wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" border="0" 
    style="background-image:url('${bgURL}'); background-size:cover; background-position:center; padding:40px 0;">
    <tr>
      <td align="center">

        <!-- Responsive container -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px; background:#ffffff; border-radius:12px;">
          <tr>
            <td style="padding:25px 20px;">

              <!-- Logo -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center">
                    <img src="${logoURL}" alt="Logo" 
                      style="max-width:170px; width:100%; height:auto; display:block; margin:auto;" />
                  </td>
                </tr>
              </table>

              <!-- Illustration -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding-top:15px;">
                    <img src="${image2URL}" alt="Illustration"
                      style="width:60%; max-width:320px; height:auto; display:block; margin:auto;" />
                  </td>
                </tr>
              </table>

              <!-- Heading -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding-top:15px;">
                    <h3 style="font-size:22px; color:#3a5fbe; margin:0; font-family: Arial, sans-serif;">
                      Set your password
                    </h3>
                  </td>
                </tr>
              </table>

              <!-- Paragraph -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding:10px 15px;">
                    <p style="font-size:15px; color:#000; margin:0; line-height:1.5;">
                      Let's make your account more secure and safe.
                    </p>
                  </td>
                </tr>
              </table>

              <!-- Button -->
              <table cellpadding="0" cellspacing="0" border="0" align="center" style="margin-top:20px;">
                <tr>
                  <td align="center">
                    <a href="${link}" style="text-decoration:none;">
                      <div style="
                        background:#1949c2;
                        color:#fff;
                        padding:12px 28px;
                        border-radius:6px;
                        font-weight:600;
                        display:inline-block;
                        font-size:15px;
                        font-family: Arial, sans-serif;
                      ">SET PASSWORD</div>
                    </a>
                  </td>
                </tr>
              </table>

              <!-- Footer small text -->
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:25px;">
                <tr>
                  <td align="center" style="font-size:10px; color:#666;">
                    <img src="${logoURL}" style="width:50px; height:13px; vertical-align:middle;" /> © •
                    <span style="text-decoration:underline; cursor:pointer;">Unsubscribe</span>
                  </td>
                </tr>

                <tr>
                  <td>
                    <hr style="border:none; border-top:1px solid #3a5fbe; margin:15px 0;" />
                  </td>
                </tr>

                <tr>
                  <td align="center" style="font-size:11px; color:#333; padding:0 20px; line-height:1.5;">
                    By setting a password, you help protect your account and personal information.<br>
                    ITI Rd, Aundh, Pune · www.creativewebsolution.in · (+91) 9326246981
                  </td>
                </tr>
              </table>

              <!-- Social Icons -->
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;">
                <tr>
                  <td align="center">
                    <a href="https://www.instagram.com/creativewebsolution99/" target="_blank">
                      <img src="${instaURL}" style="width:28px; margin:5px 8px;" />
                    </a>

                    <a href="https://www.linkedin.com/company/creativewebsolution404/" target="_blank">
                      <img src="${linkedinURL}" style="width:28px; height:25px; margin:5px 8px;" />
                    </a>
                  </td>
                </tr>
              </table>

            </td>
          </tr>
        </table>
        <!-- END responsive container -->

      </td>
    </tr>
  </table>

</body>

    `
    return html;

  } catch (error) {
    console.error(`Error generating template: ${error.message}`);
    throw new Error("Template generation failed");
  }
};

module.exports = setPasswordTemplate;
