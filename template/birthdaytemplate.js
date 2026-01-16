async function birthdaytemplate(employeeName = "Employee") {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h1 style="color: #4A90E2; text-align: center;">🎂 Happy Birthday!</h1>
      <p style="font-size: 16px;">Dear <strong>${employeeName}</strong>,</p>
      <p>Wishing you a fantastic birthday and a wonderful year ahead! 🎉🥳</p>
      <p style="font-size: 14px; color: #666;">
        Best regards,<br>
        <strong>CWS EMS Team</strong>
      </p>
    </div>
  `;
}

module.exports = birthdaytemplate;


// const logoURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346150/email-assets/hzcl6heksswnumx0dpvj.jpg";
// const bgURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346154/email-assets/lfyph07cneblr6u4eyea.png";
// const instaURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346147/email-assets/tk4elrj17odvckohcphj.png";
// const linkedinURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346149/email-assets/ly2cuolsv8left1tc1uv.png";
// const image1URL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346145/email-assets/nzblte27m1nyadkffxh8.png";
// const cakeImageURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346151/email-assets/ex1lfshnofxjigm4y2zb.jpg";

// async function birthdaytemplate(employeeName = "Employee") {
//   return `
// <table width="100%" border="0" cellspacing="0" cellpadding="0" 
//        style="margin:0; padding:0; background:#f5f5f5;">
//  <tr>
//    <td align="center" 
//        background="${bgURL}" 
//        style="
//         background-size:cover;
//         background-position:center;
//         padding:40px 0;
//        ">
//       <table width="600" 
//              cellpadding="0" 
//              cellspacing="0" 
//              border="0" 
//              style="background:#ffffff; border-radius:12px; padding:30px; text-align:center;">
        
//         <tr>
//           <td>
//             <img src="${logoURL}" 
//                  width="170" 
//                  style="display:block; margin:0 auto 20px;" 
//                  alt="CWS Logo" />
//           </td>
//         </tr>

//         <tr>
//           <td>
//             <img src="${cakeImageURL}" 
//                  width="80%" 
//                  style="display:block; margin:0 auto 20px;" 
//                  alt="Birthday Cake" />
//           </td>
//         </tr>

//         <tr>
//           <td>
//             <h2 style="font-size:28px; color:#3a5fbe; margin:0 0 15px; font-weight:600;">🎂 Happy Birthday ${employeeName}!</h2>
//           </td>
//         </tr>

//         <tr>
//           <td>
//             <p style="
//               color:#000; 
//               font-size:16px;
//               line-height:1.6;
//               margin:0 0 20px;
//               font-weight:500;
//             ">
//               Wishing you a fantastic birthday filled with joy, success, and wonderful moments ahead! 🎉🥳
//             </p>
//           </td>
//         </tr>

//         <tr>
//           <td>
//             <p style="
//               color:#000; 
//               font-size:15px;
//               line-height:1.5;
//               margin:0 0 25px;
//             ">
//               Have an amazing day and a brilliant year ahead!
//             </p>
//           </td>
//         </tr>

       

//          <tr>
//           <td style="padding-top:15px;">
//             <img src="${logoURL}" width="50" style="vertical-align:middle;" />
//             <span style="font-size:10px; color:#666;">
//               © • <a href="#" style="text-decoration:underline; color:#666;">Unsubscribe</a>
//             </span>
//           </td>
//         </tr>

       
//         <tr>
//           <td style="padding-top:20px;">
//             <hr style="border:0; border-top:1px solid #3a5fbe;">
//           </td>
//         </tr>

       
//         <tr>
//           <td style="padding-top:10px;">
//             <p style="font-size:11px; color:#333; line-height:1.4;">
//               ITI Rd, Aundh, Pune / www.creativewebsolution.in / (+91) 9326246981
//             </p>
//           </td>
//         </tr>

        
//         <tr>
//           <td style="padding-top:10px;">
//             <a href="https://www.instagram.com/creativewebsolution99/" target="_blank">
//               <img src="${instaURL}" width="28" style="margin:0 10px;">
//             </a>
//             <a href="https://www.linkedin.com/company/creativewebsolution404/" target="_blank">
//               <img src="${linkedinURL}" width="28" style="margin:0 10px;">
//             </a>
//           </td>
//         </tr>


//       </table>
//     </td>
//  </tr>
// </table>
//   `;
// }

// module.exports = birthdaytemplate;

