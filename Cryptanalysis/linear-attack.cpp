#include <iostream>
#include <vector>
#include <algorithm>
#include <utility>
#include <map>

using namespace std ; 
#define s_box_size 4 
#define s_box_range 16 
#define no_of_round  4 
#define range_p  (1 << no_of_round * s_box_size ) 
#define no_of_encryptions (1<<16) 

int S_box[16] = {0xE , 0x4 , 0xD , 0x1 , 0x2, 0xF , 0xB , 0x8 , 0x3 , 0xA , 0x6 , 0xC , 0x5 , 0x9 , 0x0 , 0x7} ;
int S_ibox[16] = {0xE , 0x3 , 0x4 , 0x8 , 0x1, 0xC , 0xA , 0xF , 0x7 , 0xD , 0x9 , 0x6 , 0xB , 0x2 , 0x0 , 0x5} ; 
int P[16] = {0x1 , 0x5 , 0x9 , 0xD , 0x2 , 0x6 , 0xA , 0xE , 0x3 , 0x7 , 0xB , 0xF , 0x4 , 0x8 , 0xC , 0x10 } ; 

int key[5]  ; 
vector<pair<int , int> > encryptions ; 

void instantiate_key(){	
	srand(time(0));
	cout << "chosen keys: " << endl ;
	/*
	key[0] = 	60239  ;
	key[1] =	7621 ; 
	key[2] =	10508 ; 
	key[3] =	28780 ; 
	key[4] =	51797 ;
	*/
	for(int i = 0 ; i < 5 ; i++)
	{
		int x = range_p ; 
		key[i] = rand() % x; 
		
	}
	
}
/*
int substitute(int p)
{
	int b0 = S_box[p & 15];	
	int b1 = S_box[(p>>4) & 15];
	int b2 = S_box[(p>>8) & 15];
	int b3 = S_box[(p>>12) & 15];
	return b0 + (b1<<4) + (b2<<8) + (b3<<12);
}

int inverse_substitute(int p)
{
	int b0 = S_ibox[p & 15];	
	int b1 = S_ibox[(p>>4) & 15];
	int b2 = S_ibox[(p>>8) & 15];
	int b3 = S_ibox[(p>>12) & 15];
	return b0 + (b1<<4) + (b2<<8) + (b3<<12);
}
*/

uint substitute(uint p)
{
	uint e = 0 ; 
	for(int i = 0 ; i < 4 ; i++)
	{
		uint x = S_box[p % s_box_range];
		//if(p % s_box_size == 0) continue ; 
		p = p >> (s_box_size) ; 
		x = x << ((s_box_size) * i) ; 
		e +=  x  ; 
	}
	return e ; 
}


uint inverse_substitute(uint p )
{
	uint e = 0 ; 
	for(int i = 0 ; i < 4 ; i++)
	{
		//if(i == 0 || i == 2) continue ; 
		uint x = S_ibox[p % s_box_range];
		p = p >> (s_box_size) ; 
		x = x << ((s_box_size) * i) ; 
		e +=  x  ; 
	}
	return e ;
}


int permute(int p)
{
	uint e = 0 ; 
	for(int i = 15 ; i >= 0 ; i--)
	{
		uint x = (p >> i) % 2 ; 
		e += ( x << (16 - P[15 - i]))  ; 
	}
	return e ;
}

int encrypt(int p) //, uint k)
{
	int e1 = permute(substitute(p ^ key[0])) ; 
	int e2 = permute(substitute(e1 ^ key[1])) ;
	int e3 = permute(substitute(e2 ^ key[2])) ;
	int e4 = (substitute(e3 ^ key[3])) ^ key[4] ;
	return e4 ; 	
}


void getencryptions()
{	int cc = 0;
	for(int i = 0 ; i <  no_of_encryptions ; i++)
	{	cc++;
		int e = encrypt(i) ; 
		encryptions.push_back(make_pair(i , e)) ; 
	}
	//cout<<cc<<" encryptions "<<encryptions.size()<<endl;
}

map<int,int> cnt;

inline bool at(int bitvector,int pos){
	pos--;
	return  ((bitvector>>pos) & 1);
}

bool check(int key,pair<int,int> texts){
	int p = texts.first;
	int e = texts.second;
	int e_intr = inverse_substitute(e ^ ( ((key & 15)) + (((key>>4) & 15)<<8) ) );
	return ((at(e_intr,1)) ^ (at(e_intr,3)) ^ (at(e_intr,9)) ^ (at(e_intr,11)) ^ (at(p,9)) ^ (at(p,10)) ^ (at(p,12))) == 0;
}

bool check2(int keyx,pair<int,int> texts){
	int p = texts.first;
	int e = texts.second;
	int e_intr = inverse_substitute(e ^ ( ((keyx & 15)) + (((keyx>>4) & 15)<<8) ) );

	int e1 = permute(substitute(p ^ key[0])) ; 
	int e2 = permute(substitute(e1 ^ key[1])) ;
	int e3 = permute(substitute(e2 ^ key[2])) ;
	int e_intr2 = e3 ^ key[3];
	bool a1 = ((at(e_intr,1)) ^ (at(e_intr,3)) ^ (at(e_intr,9)) ^ (at(e_intr,11)) ^ (at(p,9)) ^ (at(p,10)) ^ (at(p,12))) == 0;
	bool a2 = ((at(e_intr2,1)) ^ (at(e_intr2,3)) ^ (at(e_intr2,9)) ^ (at(e_intr2,11)) ^ (at(p,9)) ^ (at(p,10)) ^ (at(p,12))) == 0 ;
	if(a1 != a2) cout<<std::hex<<"Error "<< ( ((keyx & 15)) + (((keyx>>4) & 15)<<8) )<<" "<<key[4]<<"\n";
	return ((at(e_intr,1)) ^ (at(e_intr,3)) ^ (at(e_intr,9)) ^ (at(e_intr,11)) ^ (at(p,9)) ^ (at(p,10)) ^ (at(p,12))) == 0;
}


int count3;

void check_approximation(){
	count3 = 0;
	for(int i = 0 ; i <  no_of_encryptions ; i++)
	{	int p = i;
		int e1 = permute(substitute(p ^ key[0])) ; 
		int e2 = permute(substitute(e1 ^ key[1])) ;
		int e3 = permute(substitute(e2 ^ key[2])) ;
		int e_intr = e3 ^ key[3];
		if(((at(e_intr,1)) ^ (at(e_intr,3)) ^ (at(e_intr,9)) ^ (at(e_intr,11)) ^ (at(p,9)) ^ (at(p,10)) ^ (at(p,12))) == 0) count3++;
	}
	cout<<"Bias of the approximation = "<<((double)count3-32768)/(1<<16)<<endl;
}
//if(((at(e_intr,6)) ^ (at(e_intr,8)) ^ (at(e_intr,14)) ^ (at(e_intr,16)) ^ (at(p,5)) ^ (at(p,7)) ^ (at(p,8))) == 0) count3++;

int main(){

	instantiate_key();
	getencryptions();
	//cout<<"E.size() = "<<encryptions.size()<<endl;
	check_approximation();
	//cout<<"E.size() = "<<encryptions.size()<<endl;
	// try over all keys and 
	//cout<<53<< " " <<encrypt(53)<<endl;
	
	for(int i=0;i<256;i++){ // 2^4 *2^4 
		//cout<<"Key i = "<<i<<" going on \n";
		for(auto P : encryptions){
			if(check(i,P)) cnt[i]++;
		}
	}
	
	vector<pair<int,pair<int,int> > > data;

	for(auto P : cnt) {
		int x = P.second-32768;
		data.push_back(make_pair(abs(x),make_pair((P.first & 15), (P.first >> 4) & 15)));
	}	
	
    sort(data.begin(),data.end());
    reverse(data.begin(),data.end());
    for(int i=0;i<=2;i++){ // output 5 top candidates
    	cout<<std::hex<< ((double) data[i].first)/(1<<16) <<" "<<data[i].second.second<<" "<<data[i].second.first<<" "<<endl;
    }  
    for(int i=0;i<5;i++){
    	cout<<  key[i] << endl ; 
    }

    ////////////////////// check
    /*
    for(int i=0;i<5;i++){
    	cout<<std::hex<<  key[i] << endl ; 
    }
    cout<<"E.size() = "<<encryptions.size()<<endl;
    int k = (key[4] & 15) + (((key[4]>>8) & 15)<<4);
    int cc = 0;
    for(auto P : encryptions){
    	cc++;
		if(check2(k,P)) cnt[k]++;
	}
	cout<<cc<<" LLLL "<<encryptions.size()<<endl;
	cout<<abs(cnt[k]-32768)<<" "<<k<<endl;
	for(int i=0;i<(1<<16);i++){
		if(i != inverse_substitute(substitute(i))) cout<<i<<" inv wrong \n ";
	}
	*/
}
