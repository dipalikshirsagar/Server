const logoURL = "https://res.cloudinary.com/dfvumzr0q/image/upload/v1764346150/email-assets/hzcl6heksswnumx0dpvj.jpg";

const probationCompletedTemplate = async () => {
  try {
    const html = `
             <body style="
                    margin: 0;
                    padding: 0;
                    background-image: url('./assets/letterbg.png');
                    background-size: cover;
                    background-position: center;
                    background-repeat: no-repeat;
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
                        border-bottom: 10px solid #2584b0;
                        max-width: 700px;
                        width: 100%;
                        padding: 30px;
                        box-sizing: border-box;
                    ">

                    <!-- Header Section -->
                    <div style="
                        display: flex;
                        justify-content: space-between;
                        align-items: flex-start;
                        margin-bottom: 25px;
                        border-bottom: 1px solid #ccc;
                        padding-bottom: 15px;
                        ">

                        <div style="width: 50%;"></div>

                        <div style="width: 50%; text-align: right;">
                        <img 
                            src="./assets/logo.jpeg" 
                            alt="Logo"
                            style="height: 80px; object-fit: contain;"
                        />
                        </div>
                    </div>

                    <!-- Content Section -->
                    <div style="text-align: left;">

                        <p>Dear Komal,</p>

                        <h3 style="
                            margin-top: 0;
                            font-size: 20px;
                            font-weight: bold;
                        ">
                        Successful completion of your probationary period
                        </h3>

                        <p>
                        We are delighted to confirm that as of 27th November 2025 you have successfully
                        completed your six month probationary period.
                        </p>

                        <p>
                        Your yearly leave balance has now been added:
                        </p>

                        <ul style="margin-top: 5px;">
                        <li>Total leave : 21</li>
                        <li>Casual leave : 15</li>
                        <li>Sick leave: 6</li>
                        </ul>

                        <p>
                        You can check your updated leave balance on your dashboard.
                        </p>

                        <p style="margin-top: 30px;">
                        Best Regards,<br/>
                        <strong>CWS EMS Team</strong>
                        </p>
                    </div>

                    <!-- Footer -->
                    <footer style="
                        margin-top: 50px;
                        padding-top: 15px;
                        border-top: 1px solid #ccc;
                        font-size: 12px;
                        color: #555;
                        ">
                        Creative Web Solution • Registered Office: LWT, 203, C/O ITI Rd, Above PNG, Near Parihar Chowk, Aundh, Maharashtra 411007.
                    </footer>

                    </div>
                </div>
           </body>
                `;
    return html;

  } catch (error) {
    console.error(` Error generating email template: ${error.message}`);
    throw new Error("Template generation failed");
  }
};

module.exports =probationCompletedTemplate;