# from PIL import Image
# from captcha.image import ImageCaptcha
# from io import BytesIO


# def generate_captcha() -> list:
#     captchas = []
#     for _ in range(5):  # Generate 5 captchas
#         captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
#         captcha: ImageCaptcha = ImageCaptcha(
#             width=400,
#             height=220,
#             fonts=['C:/Windows/Fonts/arial.ttf'],
#             font_sizes=(40, 50, 60),
#         )
#         data: BytesIO = captcha.generate(captcha_text)
#         image: Image = Image.open(data)
#         captchas.append((image, captcha_text))
#     return captchasfrom PIL import Image


from PIL import Image
from captcha.image import ImageCaptcha
from io import BytesIO

def generate_captcha() -> tuple:
    captcha_text = 'Ragunath'  # or you can take input from user also by input()
    captcha: ImageCaptcha = ImageCaptcha(
        width=400,
        height=220,
        fonts=['C:/Windows/Fonts/arial.ttf'],
        font_sizes=(40, 50, 60),
    )
    data: BytesIO = captcha.generate(captcha_text)
    image: Image = Image.open(data)
    return image, captcha_text