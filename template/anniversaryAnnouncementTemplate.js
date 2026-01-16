const logoURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346150/email-assets/hzcl6heksswnumx0dpvj.jpg";

async function anniversaryAnnouncementTemplate(name, years) {
  return `
    <body style="
        margin: 0;
        padding: 0;
        background-color: #f4f4f4;
        font-family: Arial, Helvetica, sans-serif;
    ">

        <div style="
            width: 100%;
            display: flex;
            justify-content: center;
            padding-top: 50px;
            padding-bottom: 50px;
        ">

            <div style="
                background: #ffffff;
                border-radius: 10px;
                border: 1px solid #ddd;
                border-bottom: 10px solid #3A5FBE;
                max-width: 700px;
                width: 100%;
                padding: 30px;
                box-sizing: border-box;
            ">

                <!-- Header Section with Centered Logo -->
                <div style="
                    text-align: center;
                    margin-bottom: 25px;
                    border-bottom: 2px solid #3A5FBE;
                    padding-bottom: 15px;
                ">
                    <img 
                        src="${logoURL}" 
                        alt="CWS Logo"
                        style="height: 60px; object-fit: contain;"
                    />
                </div>

                <!-- Celebration Banner -->
                <div style="
                    background: linear-gradient(135deg, #3A5FBE 0%, #5B7FE8 100%); 
                    padding: 25px; 
                    border-radius: 8px; 
                    text-align: center;
                    margin-bottom: 25px;
                ">
                    <h1 style="color: white; margin: 0; font-size: 26px;">
                        🎉 Work Anniversary Celebration! 🎊
                    </h1>
                </div>

                <!-- Content Section -->
                <div style="text-align: left;">
                    <p style="font-size: 18px; color: #333; margin-bottom: 20px;">
                        Dear Team,
                    </p>
                    
                    <p style="font-size: 16px; color: #555; line-height: 1.6;">
                        Let's celebrate a special milestone today! 🎊
                    </p>
                    
                    <div style="
                        background-color: #E8EEFF; 
                        border-left: 4px solid #3A5FBE; 
                        padding: 15px; 
                        margin: 20px 0; 
                        border-radius: 5px;
                    ">
                        <p style="font-size: 16px; color: #3A5FBE; margin: 0; font-weight: bold;">
                            🎈 <strong>${name}</strong> is celebrating <strong>${years} ${years === 1 ? 'year' : 'years'}</strong> with CWS today!
                        </p>
                    </div>
                    
                    <p style="font-size: 16px; color: #555; line-height: 1.6;">
                        Let's take a moment to congratulate ${name} on this wonderful achievement and thank them for their dedication and contributions! 🙌
                    </p>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        Best Regards,<br>
                        <strong>CWS EMS Team</strong>
                    </p>
                </div>

               

            </div>
        </div>
    </body>
  `;
}

module.exports = anniversaryAnnouncementTemplate;
