#include <CH58x_common.h>
#define BLINKY_GPIO_PIN  GPIO_Pin_8

int main(void)
{
    SetSysClock(CLK_SOURCE_PLL_60MHz);
    GPIOA_SetBits(BLINKY_GPIO_PIN);
    GPIOA_ModeCfg(BLINKY_GPIO_PIN, GPIO_ModeOut_PP_20mA);
    while(1) {
        DelayMs(1000);
        GPIOA_InverseBits(BLINKY_GPIO_PIN);
    }
}