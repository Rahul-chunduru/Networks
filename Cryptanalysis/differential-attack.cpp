#include <iostream>
#include <vector>
#include <algorithm>
#include <utility>
#include <map>
#include <cmath>
using namespace std ; 
#define s_box_size 4 
#define s_box_range 16 
#define no_of_round  4 
#define range_p  pow(2 , no_of_round * s_box_size ) 
#define no_of_encryptions 100000 
#define permissible_prob 0.01


// structures for the attack.
struct differential
{
	uint idelta ; 
	uint odelta ; 
	double probability ;
	differential(uint i , uint o , double p)
	{
		idelta = i ; odelta = o  ; probability = p ; 
	} 
}; 

bool diff_compar( differential a , differential b)
{
	return a.probability > b.probability ; 
}


// instances...

uint S_box[16] = {0xE , 0x4 , 0xD , 0x1 , 0x2, 0xF , 0xB , 0x8 , 0x3 , 0xA , 0x6 , 0xC , 0x5 , 0x9 , 0x0 , 0x7} ;
uint S_ibox[16] = {0xE , 0x3 , 0x4 , 0x8 , 0x1, 0xC , 0xB , 0xF , 0x7 , 0xD , 0x9 , 0x6 , 0xB , 0x2 , 0x0 , 0x5} ; 
uint P[16] = {0x1 , 0x5 , 0x9 , 0xD , 0x2 , 0x6 , 0xA , 0xE , 0x3 , 0x7 , 0xB , 0xF , 0x4 , 0x8 , 0xC , 0x10 } ; 
double DDT[s_box_range][s_box_range] = {0} ;
vector<differential> differentials ; 
uint key[5]  ; 
vector<pair<uint , uint> > encryptions ; 
int selectivitiy[256] = {0} ;


///  routines for encryption...
void instantiate_key()
{
	cout << "chosen keys: " << endl ;
    srand(time(0));
	// key[0] = 	60239  ;
	// key[1] =	7621 ; 
	// key[2] =	10508 ; 
	// key[3] =	28780 ; 
	// key[4] =	51797 ;
	for(int i = 0 ; i < 5 ; i++)
	{
		
		int x = range_p ;
		//cin >> key[i] ;  
		 key[i] = rand() % x; 
		cout  << i + 1 << "   " << std::hex << key[i] << endl ; 
	}
}
uint substitute(uint p )
{
	uint e = 0 ; 
	for(int i = 0 ; i < 4 ; i++)
	{
		uint x = S_box[p % s_box_range]; 
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
		//		if(i == 0 || i == 2) continue ; 
		uint x = S_ibox[p % s_box_range];
		p = p >> (s_box_size) ; 
		x = x << ((s_box_size) * i) ; 
		e +=  x  ; 
	}
	return e ;
}


uint permute(uint p)
{
	uint e = 0 ; 
	for(int i = 15 ; i >= 0 ; i--)
	{
		uint x = (p >> i) % 2 ; 
		e += ( x << (16 - P[15 - i]))  ; 
	}
	return e ;
}
uint encrypt ( uint p ) 
{
	uint e1 = permute(substitute(p ^ key[0])) ; 
	uint e2 = permute(substitute(e1 ^ key[1])) ;
	uint e3 = permute(substitute(e2 ^ key[2])) ;
	uint e4 = (substitute(e3 ^ key[3])) ^ key[4] ;
	return e4 ; 	
}

// for debug.
uint dummy_encrypt ( uint p ) 
{
	uint e1 = permute(substitute(p ^ key[0])) ; 
	uint e2 = permute(substitute(e1 ^ key[1])) ;
	uint e3 = permute(substitute(e2 ^ key[2])) ;
	uint e4 = (substitute(e3 ^ key[3])) ^ key[4] ;
	return e3 ; 	
}
//need not use. 
void getencryptions()
{
	for(int i = 0 ; i <  range_p ; i++)
	{
		uint x = range_p ; 
		uint p = (uint) i ; 
		uint cp  = p ^ (0xB00) ; 
		uint ce = encrypt(cp) ; 
		uint e = encrypt(p) ; 
		encryptions.push_back(make_pair(p , e)) ;
		encryptions.push_back(make_pair(cp , ce)) ; 
	}
}

// routines for the attack. 
/// populates the DDT
void buildDDT()
{
	for(uint i = 0 ; i < s_box_range ; i++)
	{
		for(uint j = 0 ; j < s_box_range ; j++)
		{
			uint a = S_box[i] ; 
			uint b = S_box[j] ; 
			DDT[i ^ j][a ^ b]++ ; 
		}
	}
	//display DDT
	cout << endl <<  "DDT build complete..." << endl ; 
	cout << "Constructed DDT: " << endl ; 
	for(int i = 0  ; i < s_box_range ; i++)
	{
		for(int j = 0 ; j < s_box_range ; j++)
		{
			DDT[i][j] /= s_box_range ; 
			cout << DDT[i][j]<< " " ; 
		}
		cout << endl ; 
	}
	cout << endl ;
}

/// returns the probability of input difference and output difference of 16 bit numbers.
double probab(uint i , uint o)
{
	double prob = 1 ; 
	for(int k = 0 ; k < 4 ; k++)
	{

		uint x = (i >> 4 * k) % 16; 
		uint y = (o >> 4 * k ) % 16; 
		if((x == 0 && y != 0) || (y == 0 && x != 0)) prob = 0 ; 
		prob *= DDT[x][y] ; 
	}
	return prob ; 
}

void constructdiffs_helper( uint input , uint intermediate, double probability,  int levels)
{
	if(levels == 0)
	{
		//cout << input << " " << probability << " " << intermediate  ; 
		if(probability > permissible_prob)
		differentials.push_back(differential(input , intermediate , probability)) ;

	}
	else
	{
		for(uint x = 0 ; x < range_p ; x++ )
		{
			double f  = probab(intermediate , x); 
			if( f >= permissible_prob )
			{
				uint y = permute(x);
				//cout << y << " " << probability * f << endl ; 
				constructdiffs_helper( input , y , probability * f , levels - 1) ;  
			}
		}

	}
}

/// only constructs differentials upon 2nd and 4th bytes of output.
void constructdiffs()
{
	for(uint i = 1 ; i < s_box_range ; i++)
	{
		// we only consider these forms of inputs.
		uint input = i << ( 2 * s_box_size) ;
		//cout << input << endl ;
		constructdiffs_helper(input , input , 1 , 3) ; 
	}
}

 int s= 0 , h = 0; 
//// differential attack.
void differential_attack()
{
	differential Mdifferential = differentials[0] ; 
	cout << "\nchecking for the differential: " << Mdifferential.idelta << " " 
	<< Mdifferential.odelta <<  " " << Mdifferential.probability << endl; 
	for(int i = 0 ; i < range_p ; i++)
	{
			uint c1 = encrypt(i) ; 
			uint c2 = encrypt(i ^ Mdifferential.idelta) ; 
			// if((encryptions[i].first ^ encryptions[j].first) != Mdifferential.idelta) continue ; 
			s++ ;
			for(int i = 0 ; i < 256 ; i++)
			{
				uint key = i % 16 + ((i >> 4) << 8) ; 
				uint pdec1 = c1 ^ key ; 
				uint pdec2 = c2 ^ key ;
				uint pd1 = inverse_substitute(pdec1) ; 
				uint pd2 = inverse_substitute(pdec2) ; 
				if((pd1 ^ pd2) == Mdifferential.odelta) { selectivitiy[i]++  ; h++ ;  }  
			}
	}
	cout << "total right pairs: " << s << "      hit: " << h <<  endl ; 
}
// bool ispossilble()
// {
// 	for(int i = 0 ; i < range_p ; i++ )
// 	{
// 		uint j = i ^ (0xB00) ; 
// 		uint c1 = dummy_encrypt(i) ; 
// 		uint c2 = dummy_encrypt(j) ; 
// 		uint f =  (c1 ^ c2) ; 
		
// 		if(f == 1542)
// 		{ 
// 			return 1 ;  
// 			if(( substitute( c1 ^key[3]) ^ key[4] ) == encrypt(i)) cout << "true also\n" ; 
// 			if(( substitute( c2 ^key[3]) ^ key[4] ) == encrypt(j)) cout << "great also\n" ; 
// 		}

// 	}
// 	return 0 ; 
// }

int main()
{
	instantiate_key() ; 
	// The differential cryptanalysis attack.
	// first build the differential characteristics(DDT) of an unkeyed S-box.
	buildDDT() ;
	// construct differentials from DDT
	constructdiffs() ;  
	sort(differentials.begin() , differentials.end() , diff_compar) ; 
	cout << "the more probable diffrentials" << endl ; 
	for(int i = 0 ; i < differentials.size()  ; i++)
	{
		cout << differentials[i].idelta << " " << differentials[i].odelta << " " << differentials[i].probability << endl ; 
	}

	/// populations the encryptions.
	//getencryptions() ; 
	// extract key bits.
	// if(!(ispossilble())){ cout << "keys not random enough..\n" ; return 0;} 
	differential_attack() ; 
	 
	 cout << "More probable key(s) bits.\n" ;
	 int max_select  = -1 ;  
	 for(int i = 0 ; i < 256 ; i++) max_select = max(max_select , selectivitiy[i]) ; 
	 for(int i = 0 ; i < 256 ; i++)
	 {
	 	if( (selectivitiy[i] == 0) || (selectivitiy[i] < max_select / 4) ) continue ; 
	 	cout << std::hex << (i % 16 + ((i >> 4) << 8))  ; 
	 	cout << std::dec <<  " " << (selectivitiy[i] * 1.0) / s << endl ; 
	
	 }
	 uint r_select = selectivitiy[key[4] % 16 + (((key[4]  >> 8) % 16)<< 4)] ; 
	 cout << "\n\ncorrect key" << " " << std::hex << (key[4] & (0xF0F))  ; 
	 cout << std::dec << "\nit's selectivitiy " << (r_select * 1.0) / s << endl ;
	 
	 cout << " \n\nResult :-\n" ; 
	 if(r_select >= max_select / 4) cout << "successfully reduced the key space !!!" ; 
	 else cout << "Attack didn't give any correct results..." ; 
}