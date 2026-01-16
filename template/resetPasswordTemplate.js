const logoURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346150/email-assets/hzcl6heksswnumx0dpvj.jpg";
const bgURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346154/email-assets/lfyph07cneblr6u4eyea.png";
const instaURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346147/email-assets/tk4elrj17odvckohcphj.png";
const linkedinURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346149/email-assets/ly2cuolsv8left1tc1uv.png";
const image1URL="https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346145/email-assets/nzblte27m1nyadkffxh8.png"
const image2URL="https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346151/email-assets/ex1lfshnofxjigm4y2zb.jpg"


const resetPasswordTemplate = (link) => {

return `
<table width="100%" border="0" cellspacing="0" cellpadding="0" 
       style="margin:0; padding:0; background:#f5f5f5;">
  <tr>
    <td align="center" 
        background="${bgURL}" 
        style="
          background-size:cover;
          background-position:center;
          padding:40px 0;
        "
    >

   
      <table width="600" 
             cellpadding="0" 
             cellspacing="0" 
             border="0" 
             style="background:#ffffff; border-radius:12px; padding:30px; text-align:center;">
        
      
        <tr>
          <td>
            <img src="${logoURL}" 
                 width="170" 
                 style="display:block; margin:0 auto 20px;" 
                 alt="Logo" />
          </td>
        </tr>

        
        <tr>
          <td>
            <img src="${image1URL}" 
                 width="80%" 
                 style="display:block; margin:0 auto 20px;" />
          </td>
        </tr>

       
        <tr>
          <td>
            <h3 style="font-size:24px; color:#3a5fbe; margin:0 0 15px;">Forgot your password?</h3>
          </td>
        </tr>

        
        <tr>
          <td>
            <p style="
              color:#000; 
              font-size:15px;
              line-height:1.5;
              margin:0 0 15px;
            ">
              We received a request to reset your password.<br/>
              If you didn’t make this request, simply ignore this email.
            </p>
          </td>
        </tr>

       
        <tr>
          <td>
            <a href="${link}" 
               style="
                 display:inline-block;
                 background:#1949c2;
                 color:#fff;
                 padding:12px 28px;
                 text-decoration:none;
                 border-radius:6px;
                 font-weight:600;
                 margin-top:10px;
               ">
               RESET PASSWORD
            </a>
          </td>
        </tr>

        
        <tr>
          <td style="padding-top:15px;">
            <img src="${logoURL}" width="50" style="vertical-align:middle;" />
            <span style="font-size:10px; color:#666;">
              © • <a href="#" style="text-decoration:underline; color:#666;">Unsubscribe</a>
            </span>
          </td>
        </tr>

       
        <tr>
          <td style="padding-top:20px;">
            <hr style="border:0; border-top:1px solid #3a5fbe;">
          </td>
        </tr>

       
        <tr>
          <td style="padding-top:10px;">
            <p style="font-size:11px; color:#333; line-height:1.4;">
              We take your security seriously. Only proceed if you requested this reset.<br/>
              ITI Rd, Aundh, Pune / www.creativewebsolution.in / (+91) 9326246981
            </p>
          </td>
        </tr>

        
        <tr>
          <td style="padding-top:10px;">
            <a href="https://www.instagram.com/creativewebsolution99/" target="_blank">
              <img src="${instaURL}" width="28" style="margin:0 10px;">
            </a>
            <a href="https://www.linkedin.com/company/creativewebsolution404/" target="_blank">
              <img src="${linkedinURL}" width="28" style="margin:0 10px;">
            </a>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
`;
};

module.exports = resetPasswordTemplate;


 