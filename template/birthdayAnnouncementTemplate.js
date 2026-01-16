async function birthdayAnnouncementTemplate(birthdayPersonName) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
        <h1 style="color: white; margin: 0; font-size: 28px;">🎂 Birthday Celebration! 🎉</h1>
      </div>
      
      <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
        <p style="font-size: 18px; color: #333; margin-bottom: 20px;">
          Dear Team,
        </p>
        
        <p style="font-size: 16px; color: #555; line-height: 1.6;">
          Today is a special day! 🎊
        </p>
        
        <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px;">
          <p style="font-size: 18px; color: #856404; margin: 0; font-weight: bold;">
            🎈 <strong>${birthdayPersonName}</strong> is celebrating birthday today!
          </p>
        </div>
        
        <p style="font-size: 16px; color: #555; line-height: 1.6;">
          Let's take a moment to wish them a wonderful day filled with happiness and success! 🥳
        </p>
        
        <p style="font-size: 14px; color: #666; margin-top: 30px;">
          Warm regards,<br>
          <strong>CWS EMS Team</strong>
        </p>
      </div>
    </div>
  `;
}

module.exports = birthdayAnnouncementTemplate;
